// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const (
	unlockedApp    = "testdata/unlocked/src/App"
	unlockedLegacy = "testdata/unlocked/src/Legacy"
)

func TestReferenceVersion(t *testing.T) {
	t.Parallel()
	for requested, expected := range map[string]string{
		"13.0.3":          "13.0.3",
		"1.0":             "1.0",
		"8.0.0-preview.1": "8.0.0-preview.1",
		"1.2.3.4":         "1.2.3.4",
		"1.0.0+build.5":   "1.0.0+build.5",
		" 2.0.0 ":         "2.0.0",
		"[4.2.0]":         "4.2.0",
		"[1.0, 2.0)":      "",
		"[1.0,)":          "",
		"(,2.0]":          "",
		"8.*":             "",
		"*":               "",
		"1.0.0-beta.*":    "",
		"$(NotFilledIn)":  "",
		"":                "",
	} {
		reference := &Reference{Requested: requested}
		require.Equal(t, expected, reference.Version(), requested)
	}
}

func TestParseProject(t *testing.T) {
	t.Parallel()
	project, err := ReadProject(filepath.Join(unlockedApp, "Demo.App.csproj"))
	require.NoError(t, err, "a byte order mark opens the file")

	ids := make([]string, 0, len(project.References))
	byID := map[string]*Reference{}
	for _, reference := range project.References {
		ids = append(ids, reference.ID)
		byID[reference.ID] = reference
	}
	// An Update changes an item declared elsewhere and names no package
	// of its own.
	require.Equal(t, []string{
		"Newtonsoft.Json", "serilog", "Polly", "Overridden", "Local.Lib", "Unknown.Prop", "Floating", "Exact",
		"No.Version.Anywhere", "xunit", "Microsoft.SourceLink.GitHub", "Roslynator.Analyzers", "System.Memory",
		"Windows.Only",
	}, ids)

	require.Equal(t, "3.0.0", byID["Overridden"].Requested, "an override is the version")
	require.Equal(t, "$(LocalVersion)", byID["Local.Lib"].Requested, "as written, until the properties are filled in")
	// Private in an attribute and in a child element, in any case.
	require.True(t, byID["Microsoft.SourceLink.GitHub"].Private)
	require.True(t, byID["Roslynator.Analyzers"].Private)
	require.Equal(t, "4.12.0", byID["Roslynator.Analyzers"].Requested)
	require.False(t, byID["Newtonsoft.Json"].Private)
	// The condition of an item group, and of a branch of a Choose.
	require.Equal(t, "'$(TargetFramework)' == 'net48'", byID["System.Memory"].Condition)
	require.Equal(t, "'$(OS)' == 'Windows_NT'", byID["Windows.Only"].Condition)

	require.Equal(t, []string{`..\Core\Demo.Core.csproj`}, project.ProjectReferences)
	require.Equal(t, "2.5.0", project.Properties["localversion"])

	central, err := ReadProject("testdata/unlocked/Directory.Packages.props")
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"newtonsoft.json": "13.0.3", "serilog": "$(SerilogVersion)", "polly": "[8.0.0, 9.0.0)", "overridden": "1.0.0",
	}, central.Central)
	require.Len(t, central.Global, 1)
	require.True(t, central.Global[0].Private, "a global reference is private by definition")

	// The older, namespaced kind of project file reads too.
	legacy, err := ReadProject(filepath.Join(unlockedLegacy, "Legacy.csproj"))
	require.NoError(t, err)
	require.Empty(t, legacy.References)
	require.Equal(t, "v4.7.2", legacy.Properties["targetframeworkversion"])

	_, err = ParseProject([]byte("<Project><ItemGroup>"))
	require.Error(t, err)
}

func TestExpandProperties(t *testing.T) {
	t.Parallel()
	near := map[string]string{"a": "1.0", "nested": "$(A)-rc"}
	far := map[string]string{"a": "9.9", "b": "2.0"}
	require.Equal(t, "1.0", expandProperties("$(A)", near, far), "the nearest definition, whatever the case")
	require.Equal(t, "2.0", expandProperties("$(B)", near, far))
	require.Equal(t, "1.0-rc", expandProperties("$(Nested)", near, far))
	require.Equal(t, "$(Unknown)", expandProperties("$(Unknown)", near, far))
	require.Equal(t, "3.0", expandProperties("3.0", near, far))
}

type unlockedDep struct {
	edge sbom.Edge_Type
	node *sbom.Node
}

func extractUnlocked(t *testing.T, dir string, opts *api.DecomposerOptions) (root *sbom.Node, deps map[string]unlockedDep) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	byID := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
	}
	deps = map[string]unlockedDep{}
	for _, e := range nl.GetEdges() {
		require.Equal(t, roots[0].GetId(), e.GetFrom(), "the graph is flat")
		for _, to := range e.GetTo() {
			deps[byID[to].GetName()] = unlockedDep{e.GetType(), byID[to]}
		}
	}
	require.Len(t, deps, len(byID)-1)
	return roots[0], deps
}

func TestExtractUnlocked(t *testing.T) {
	t.Parallel()
	root, deps := extractUnlocked(t, unlockedApp, &api.DecomposerOptions{})
	require.Equal(t, "Demo.App", root.GetName())

	versions := map[string]string{}
	for name, dep := range deps {
		require.Equal(t, sbom.Edge_dependsOn, dep.edge, name)
		versions[name] = dep.node.GetVersion()
	}
	require.Equal(t, map[string]string{
		// From the central file, a property of it filled in, and the id
		// matched whatever its case.
		"Newtonsoft.Json": "13.0.3",
		"serilog":         "3.1.1",
		// A range and a floating version resolve to what only a restore
		// knows.
		"Polly":    "",
		"Floating": "",
		"Exact":    "4.2.0",
		// The project's own word over the central file's, its own
		// property, and one from the props file above it.
		"Overridden": "3.0.0",
		"Local.Lib":  "2.5.0",
		"xunit":      "2.8.0",
		// A property nothing in the source defines, and no version
		// anywhere.
		"Unknown.Prop":        "",
		"No.Version.Anywhere": "",
		"System.Memory":       "4.5.5",
		"Windows.Only":        "1.0.0",
		// Another project of the solution.
		"Demo.Core": "",
		// What the props file above gives every project below it.
		"Shared.Everywhere": "1.2.3",
	}, versions)

	require.Equal(t, "pkg:nuget/Newtonsoft.Json@13.0.3", string(deps["Newtonsoft.Json"].node.Purl()))
	require.Equal(t, map[string][]string{
		PropertyType:      {TypeDirect},
		PropertyReadFrom:  {ReadFromProject},
		PropertyRequested: {"13.0.3"},
	}, properties(deps["Newtonsoft.Json"].node))
	require.Equal(t, []string{"[8.0.0, 9.0.0)"}, properties(deps["Polly"].node)[PropertyRequested])
	require.Equal(t, []string{"$(SetOnTheCommandLine)"}, properties(deps["Unknown.Prop"].node)[PropertyRequested])
	require.Empty(t, properties(deps["No.Version.Anywhere"].node)[PropertyRequested])
	require.Equal(t, []string{"'$(TargetFramework)' == 'net48'"}, properties(deps["System.Memory"].node)[PropertyCondition])

	project := deps["Demo.Core"].node
	require.Equal(t, "pkg:generic/Demo.Core", string(project.Purl()))
	require.Equal(t, []string{TypeProject}, properties(project)[PropertyType])

	// What does not flow to the project's users waits for the flag: the
	// analyzers, and the repository's global reference.
	_, deps = extractUnlocked(t, unlockedApp, &api.DecomposerOptions{IncludeDev: true})
	require.Len(t, deps, 18)
	for _, name := range []string{
		"Microsoft.SourceLink.GitHub", "Roslynator.Analyzers", "Nerdbank.GitVersioning", "DotNet.ReproducibleBuilds",
	} {
		require.Equal(t, sbom.Edge_devDependency, deps[name].edge, name)
	}
	require.Equal(t, "3.6.133", deps["Nerdbank.GitVersioning"].node.GetVersion())
}

func TestExtractPackagesConfig(t *testing.T) {
	t.Parallel()
	root, deps := extractUnlocked(t, unlockedLegacy, &api.DecomposerOptions{IncludeDev: true})
	require.Equal(t, "Legacy", root.GetName())
	require.Len(t, deps, 3)

	require.Equal(t, sbom.Edge_dependsOn, deps["jQuery"].edge)
	require.Equal(t, "pkg:nuget/jQuery@3.1.1", string(deps["jQuery"].node.Purl()))
	require.Equal(t, map[string][]string{
		PropertyReadFrom: {ReadFromPackagesConfig},
		PropertyTarget:   {"net472"},
	}, properties(deps["jQuery"].node))
	require.Equal(t, sbom.Edge_devDependency, deps["StyleCop.Analyzers"].edge)

	_, deps = extractUnlocked(t, unlockedLegacy, &api.DecomposerOptions{})
	require.Len(t, deps, 2)
}

// TestLockfileWins checks a project with a lockfile is read from it, the
// project file beside it only naming the project.
func TestLockfileWins(t *testing.T) {
	t.Parallel()
	_, nodes, _ := extract(t, "testdata/app", &api.DecomposerOptions{})
	for _, node := range nodes {
		require.Empty(t, properties(node)[PropertyReadFrom], node.GetName())
	}
}

func TestExtractUnlockedErrors(t *testing.T) {
	t.Parallel()
	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.ErrorContains(t, err, "no packages.lock.json, project file or packages.config")

	// A project file that is not XML is left out, and the project is
	// still there.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Broken.csproj"), []byte("<Project><ItemGroup>"), 0o600))
	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: dir})
	require.NoError(t, err)
	require.Len(t, nl.GetNodes(), 1)
}

func TestFindCodeBasesUnlocked(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add("locked", LockFile)
	index.Add("cs", "App.csproj")
	index.Add("fs", "Lib.fsproj")
	index.Add("vb", "Old.vbproj")
	index.Add("legacy", PackagesConfigFile)
	// A repository's props files are no project, nor is a solution.
	index.Add("root", CentralVersionsFile)
	index.Add("root", "Everything.sln")
	index.Add("odd", ".csproj")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"cs", "fs", "legacy", "locked", "vb"}, found)
}

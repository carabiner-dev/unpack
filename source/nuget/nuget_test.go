// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

func TestParseLock(t *testing.T) {
	t.Parallel()

	lock, err := ReadLock("testdata/app/packages.lock.json")
	require.NoError(t, err)
	require.Equal(t, 2, lock.Version)
	require.Len(t, lock.Targets, 3)

	framework := lock.Targets[0]
	require.Equal(t, ".NETFramework,Version=v4.8", framework.Name)
	require.Equal(t, ".NETFramework,Version=v4.8", framework.Framework)
	require.Empty(t, framework.Runtime)
	require.Len(t, framework.Entries, 4)

	serilog := framework.Find("serilog")
	require.NotNil(t, serilog, "ids are found whatever their case")
	require.Equal(t, TypeDirect, serilog.Type)
	require.Equal(t, "[3.1.1, )", serilog.Requested)
	require.Equal(t, "3.1.1", serilog.Resolved)
	require.Equal(t, []Dependency{{ID: "System.Core", Range: "4.0.0"}, {ID: "System.Memory", Range: "4.5.4"}}, serilog.Dependencies)

	runtime := lock.Targets[2]
	require.Equal(t, "net8.0/win-x64", runtime.Name)
	require.Equal(t, "net8.0", runtime.Framework)
	require.Equal(t, "win-x64", runtime.Runtime)

	// The third schema keys targets by alias at the root, and states the
	// framework beside the entries.
	lock, err = ReadLock("testdata/aliased/packages.lock.json")
	require.NoError(t, err)
	require.Equal(t, 3, lock.Version)
	require.Len(t, lock.Targets, 2, "what is no target is passed over")
	require.Equal(t, "client", lock.Targets[0].Name)
	require.Equal(t, "net9.0", lock.Targets[0].Framework)
	// A type in another case is read, and a missing one is Direct.
	require.Equal(t, TypeTransitive, lock.Targets[0].Find("Polly.Core").Type)
	require.Equal(t, TypeDirect, lock.Targets[1].Find("Polly.Core").Type)

	// A byte order mark, and a project with no dependencies.
	lock, err = ParseLock(append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"version": 1, "dependencies": {"net8.0": {}}}`)...))
	require.NoError(t, err)
	require.Len(t, lock.Targets, 1)
	require.Empty(t, lock.Targets[0].Entries)

	for name, data := range map[string]string{
		"not json":          `nope`,
		"no version":        `{"dependencies": {}}`,
		"targets no object": `{"version": 1, "dependencies": []}`,
	} {
		_, err := ParseLock([]byte(data))
		require.ErrorIs(t, err, ErrMalformed, name)
	}
}

func properties(node *sbom.Node) map[string][]string {
	out := map[string][]string{}
	for _, property := range node.GetProperties() {
		out[property.GetName()] = append(out[property.GetName()], property.GetData())
	}
	return out
}

// extract returns the root, the nodes by "name@version" and the edges as
// "from -> to" by those names.
func extract(t *testing.T, dir string, opts *api.DecomposerOptions) (root *sbom.Node, nodes map[string]*sbom.Node, edges map[string]bool) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)

	label := func(node *sbom.Node) string {
		if node.GetVersion() == "" || node.GetId() == roots[0].GetId() {
			return node.GetName()
		}
		return node.GetName() + "@" + node.GetVersion()
	}
	byID := map[string]*sbom.Node{}
	nodes = map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
		nodes[label(node)] = node
	}
	require.Len(t, nodes, len(byID), "a package at a version is one node")
	edges = map[string]bool{}
	for _, e := range nl.GetEdges() {
		require.Equal(t, sbom.Edge_dependsOn, e.GetType())
		for _, to := range e.GetTo() {
			edges[label(byID[e.GetFrom()])+" -> "+label(byID[to])] = true
		}
	}
	return roots[0], nodes, edges
}

func TestExtract(t *testing.T) {
	t.Parallel()
	root, nodes, edges := extract(t, "testdata/app", &api.DecomposerOptions{Version: "v2.0.0", CommitHash: "abc"})

	// Named after the project file beside the lockfile.
	require.Equal(t, "Demo.App", root.GetName())
	require.Equal(t, "pkg:nuget/Demo.App@v2.0.0", string(root.Purl()))
	require.Len(t, root.GetExternalReferences(), 1)

	// The union of the targets' graphs.
	require.Equal(t, map[string]bool{
		// What the project references: packages and a project.
		"Demo.App -> Newtonsoft.Json@13.0.3": true,
		"Demo.App -> Serilog@3.1.1":          true,
		"Demo.App -> demo.core":              true,
		"Demo.App -> Native.Runtime@2.0.0":   true,
		// On .NET Framework, Serilog needs System.Memory, which needs
		// System.Buffers; the id is matched whatever its case, and
		// System.Core, which no package provides, is no node.
		"Serilog@3.1.1 -> System.Memory@4.5.5":        true,
		"System.Memory@4.5.5 -> System.Buffers@4.5.1": true,
		// The project referenced brings a package pinned centrally.
		"demo.core -> Microsoft.Extensions.Logging.Abstractions@8.0.1": true,
		// Resolved for net8.0 and required by nothing there: kept, from
		// the project.
		"Demo.App -> System.Memory@4.6.0": true,
		"Demo.App -> Orphan.Pinned@1.0.0": true,
		// A runtime's own package depends on one the framework's
		// resolution has.
		"Native.Runtime@2.0.0 -> Newtonsoft.Json@13.0.3": true,
	}, edges)

	// One node for a package two targets resolve alike, named for both.
	json := nodes["Newtonsoft.Json@13.0.3"]
	require.Equal(t, "pkg:nuget/Newtonsoft.Json@13.0.3", string(json.Purl()))
	require.Equal(t, map[string][]string{
		PropertyType:        {TypeDirect},
		PropertyRequested:   {"[13.0.3, )"},
		PropertyContentHash: {"HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="},
		PropertyTarget:      {".NETFramework,Version=v4.8", "net8.0"},
	}, properties(json))
	require.Empty(t, json.GetHashes(), "the content hash is not the hash of the file a feed serves")

	// Two nodes for one two targets resolve to two versions.
	require.Equal(t, []string{".NETFramework,Version=v4.8"}, properties(nodes["System.Memory@4.5.5"])[PropertyTarget])
	require.Equal(t, []string{"net8.0"}, properties(nodes["System.Memory@4.6.0"])[PropertyTarget])
	require.Equal(t, []string{"net8.0/win-x64"}, properties(nodes["Native.Runtime@2.0.0"])[PropertyTarget])

	// A project of the solution is no package of a feed.
	project := nodes["demo.core"]
	require.Empty(t, project.GetVersion())
	require.Equal(t, "pkg:generic/demo.core", string(project.Purl()))
	require.Equal(t, []string{TypeProject}, properties(project)[PropertyType])

	require.Equal(t, []string{TypeCentralTransitive},
		properties(nodes["Microsoft.Extensions.Logging.Abstractions@8.0.1"])[PropertyType])
}

func TestExtractAliased(t *testing.T) {
	t.Parallel()
	root, nodes, edges := extract(t, "testdata/aliased", &api.DecomposerOptions{})
	require.Equal(t, "aliased", root.GetName(), "the directory, with no project file to go by")
	require.Equal(t, map[string]bool{
		"aliased -> Polly@8.4.0":          true,
		"Polly@8.4.0 -> Polly.Core@8.4.0": true,
		"aliased -> Polly.Core@8.4.0":     true,
	}, edges)
	// How the project comes to have it differs by target, and both are
	// said.
	require.Equal(t, []string{TypeTransitive, TypeDirect}, properties(nodes["Polly.Core@8.4.0"])[PropertyType])
	require.Equal(t, []string{"client", "server"}, properties(nodes["Polly.Core@8.4.0"])[PropertyTarget])
}

func TestExtractErrors(t *testing.T) {
	t.Parallel()
	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.Error(t, err)
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add("src/App", "App.csproj")
	index.Add("src/App", LockFile)
	// Restored without a lockfile.
	index.Add("src/Lib", "Lib.csproj")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"src/App"}, found)
}

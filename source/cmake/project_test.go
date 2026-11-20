// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmake

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const fixture = "testdata/project"

// TestReadProject reads the fixture, which holds one of each thing the
// reader tells apart.
func TestReadProject(t *testing.T) {
	t.Parallel()
	project, err := ReadProject(fixture)
	require.NoError(t, err)
	require.Equal(t, "demo", project.Name)
	require.Equal(t, "1.4.0", project.Version)
	require.Empty(t, project.Skipped)

	deps := map[string]*Dependency{}
	names := make([]string, 0, len(project.Dependencies))
	for _, dep := range project.Dependencies {
		deps[dep.Name] = dep
		names = append(names, dep.Name)
	}
	// PkgConfig and Threads are no packages; YAMLCPP is the project's
	// name for yaml-cpp; what the vendored and the standalone projects
	// ask for is theirs.
	require.Equal(t, []string{
		"Boost", "CUDAToolkit", "CURL", "fmt", "GTest", "liblz4", "OpenSSL", "Python3", "RapidCheck",
		"Snappy", "tinyxml", "unpinned", "Vulkan", "WinSock", "WolfSSL", "yaml-cpp", "ZLIB",
	}, names)

	for name, expected := range map[string]Status{
		"ZLIB":  StatusRequired,
		"Boost": StatusRequired,
		// No REQUIRED where the project asks first, REQUIRED where the
		// tests do: the surest request counts.
		"Snappy":   StatusRequired,
		"yaml-cpp": StatusRequired,
		"Python3":  StatusOptional,
		// An option that is on, and the branch it leaves out.
		"OpenSSL": StatusRequired,
		"WolfSSL": StatusDisabled,
		// Behind the result of a lookup and behind the platform.
		"liblz4":  StatusConditional,
		"WinSock": StatusConditional,
		// Behind an option that is off, after a branch nobody can tell.
		"Vulkan": StatusDisabled,
		// In a directory only entered with that option.
		"CUDAToolkit": StatusDisabled,
		// Fetched: built with the project.
		"fmt":      StatusRequired,
		"tinyxml":  StatusRequired,
		"unpinned": StatusRequired,
		// What the tests ask for is asked for like the rest: nothing in
		// the files says a package is for the tests alone.
		"GTest":      StatusRequired,
		"RapidCheck": StatusRequired,
		// In a function: taken as called.
		"CURL": StatusRequired,
	} {
		require.Contains(t, deps, name)
		require.Equal(t, expected.String(), deps[name].Status.String(), name)
	}

	// Versions: a lookup states a range, EXACT and a fetched tag pin.
	require.Empty(t, deps["ZLIB"].Version)
	require.Equal(t, ">=1.2.11", deps["ZLIB"].Constraint)
	require.Equal(t, "1.74", deps["Boost"].Version)
	require.Equal(t, "3.0...<4", deps["OpenSSL"].Constraint)
	require.Equal(t, ">=1.9", deps["liblz4"].Constraint)
	require.Equal(t, []string{"liblz4"}, deps["liblz4"].PkgConfig)

	// The find module's lookup is the wrapped package's.
	require.Equal(t, ">=0.6", deps["yaml-cpp"].Constraint)
	require.Equal(t, []string{"yaml-cpp"}, deps["yaml-cpp"].PkgConfig)
	require.Equal(t, []string{"CMakeLists.txt:15"}, deps["yaml-cpp"].Declared)

	// A tag in a variable the files set is resolved; one they do not
	// set leaves the version unknown.
	require.Equal(t, "11.1.2", deps["fmt"].Version)
	require.Equal(t, "https://github.com/fmtlib/fmt.git", deps["fmt"].Repository)
	require.Empty(t, deps["unpinned"].Version)
	require.Equal(t, "https://example.com/tinyxml-2.6.2.tar.gz", deps["tinyxml"].URL)
	require.Equal(t, "SHA256", deps["tinyxml"].HashAlgo)
	require.Equal(t, "15bdfdcec58a7da30adc87ac2a078e4417dbe5392f3afb719f9ba6d062645593", deps["tinyxml"].Hash)

	require.Equal(t, []string{"CMakeLists.txt:12", "src/CMakeLists.txt:1"}, deps["ZLIB"].Declared)
	require.Equal(t, []string{"find_package"}, deps["ZLIB"].Commands)
}

func TestReadProjectNoListsFile(t *testing.T) {
	t.Parallel()
	_, err := ReadProject(t.TempDir())
	require.Error(t, err)
}

// TestReadProjectBrokenFile checks a file with a mistake is named and what
// came before the mistake is kept.
func TestReadProjectBrokenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, listsFile),
		[]byte("project(broken)\nfind_package(ZLIB REQUIRED)\nfind_package(Never"), 0o600))

	project, err := ReadProject(dir)
	require.NoError(t, err)
	require.Equal(t, []string{listsFile}, project.Skipped)
	require.Len(t, project.Dependencies, 1)
	require.Equal(t, "ZLIB", project.Dependencies[0].Name)
}

func TestEvaluate(t *testing.T) {
	t.Parallel()
	r := &reader{
		variables: map[string]string{"NAMED": "value", "EMPTY": "", "FLAG": "OFF", "TWICE": "a"},
		ambiguous: map[string]bool{"TWICE": true},
		options:   map[string]bool{"OPT_ON": true, "OPT_OFF": false},
	}
	for condition, expected := range map[string]conditionState{
		"ON":                     stateOn,
		"0":                      stateOff,
		"OPT_ON":                 stateOn,
		"OPT_OFF":                stateOff,
		"NOT OPT_OFF":            stateOn,
		"NOT NOT OPT_OFF":        stateOff,
		"NAMED":                  stateOn,
		"EMPTY":                  stateOff,
		"FLAG":                   stateOff,
		"${FLAG}":                stateOff,
		"TWICE":                  stateUnknown,
		"WIN32":                  stateUnknown,
		"FOO_FOUND":              stateUnknown,
		"OPT_ON AND OPT_OFF":     stateOff,
		"OPT_ON AND WIN32":       stateUnknown,
		"OPT_OFF AND WIN32":      stateOff,
		"OPT_ON OR WIN32":        stateOn,
		"OPT_OFF OR WIN32":       stateUnknown,
		"OPT_OFF OR NOT OPT_OFF": stateOn,
		"A STREQUAL B":           stateUnknown,
		"DEFINED OPT_ON":         stateUnknown,
		"( OPT_ON )":             stateUnknown,
		"":                       stateOff,
	} {
		commands, err := Parse("if(" + condition + ")")
		require.NoError(t, err)
		require.Equal(t, expected, r.evaluate(commands[0].Args), condition)
	}
}

func extract(t *testing.T, opts *api.DecomposerOptions) (root *sbom.Node, byName map[string]*sbom.Node, edges map[string]sbom.Edge_Type) {
	t.Helper()
	opts.WorkDir = fixture
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)

	byName = map[string]*sbom.Node{}
	byID := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byName[node.GetName()] = node
		byID[node.GetId()] = node
	}
	edges = map[string]sbom.Edge_Type{}
	for _, edge := range nl.GetEdges() {
		require.Equal(t, roots[0].GetId(), edge.GetFrom(), "the graph is flat")
		for _, to := range edge.GetTo() {
			edges[byID[to].GetName()] = edge.GetType()
		}
	}
	return roots[0], byName, edges
}

func TestExtract(t *testing.T) {
	t.Parallel()

	// By default, what the default configuration asks for: what it
	// requires, and as optional dependencies what it goes on without and
	// what is behind a condition the files do not settle. What an option
	// turns off is left out.
	root, nodes, edges := extract(t, &api.DecomposerOptions{})
	require.Equal(t, "demo", root.GetName())
	require.Equal(t, "1.4.0", root.GetVersion())
	require.Equal(t, "pkg:generic/demo@1.4.0", string(root.Purl()))
	require.Equal(t, map[string]sbom.Edge_Type{
		"Boost": sbom.Edge_dependsOn, "CURL": sbom.Edge_dependsOn, "fmt": sbom.Edge_dependsOn,
		"OpenSSL": sbom.Edge_dependsOn, "Snappy": sbom.Edge_dependsOn, "tinyxml": sbom.Edge_dependsOn,
		"unpinned": sbom.Edge_dependsOn, "yaml-cpp": sbom.Edge_dependsOn, "ZLIB": sbom.Edge_dependsOn,
		"GTest": sbom.Edge_dependsOn, "RapidCheck": sbom.Edge_dependsOn,
		"liblz4": sbom.Edge_optionalDependency, "WinSock": sbom.Edge_optionalDependency,
		"Python3": sbom.Edge_optionalDependency,
	}, edges)

	require.Equal(t, "pkg:github/fmtlib/fmt@11.1.2", string(nodes["fmt"].Purl()))
	require.Equal(t, "pkg:gitlab/group/sub/unpinned", string(nodes["unpinned"].Purl()))
	require.Equal(t, "pkg:generic/Boost@1.74", string(nodes["Boost"].Purl()))
	require.Equal(t, "pkg:generic/ZLIB", string(nodes["ZLIB"].Purl()))
	require.Equal(t, "https://example.com/tinyxml-2.6.2.tar.gz", nodes["tinyxml"].GetUrlDownload())
	require.Equal(t, "15bdfdcec58a7da30adc87ac2a078e4417dbe5392f3afb719f9ba6d062645593",
		nodes["tinyxml"].GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	properties := map[string][]string{}
	for _, property := range nodes["ZLIB"].GetProperties() {
		properties[property.GetName()] = append(properties[property.GetName()], property.GetData())
	}
	require.Equal(t, map[string][]string{
		PropertyStatus:     {"required"},
		PropertyConstraint: {">=1.2.11"},
		PropertyCommand:    {"find_package"},
		PropertyDeclared:   {"CMakeLists.txt:12", "src/CMakeLists.txt:1"},
	}, properties)

	// The optional flag adds what an option turns off. The other two
	// flags add nothing: the files do not say what a package is for.
	_, _, edges = extract(t, &api.DecomposerOptions{IncludeOptional: true})
	require.Len(t, edges, 17)
	require.Equal(t, sbom.Edge_optionalDependency, edges["WolfSSL"])
	require.Equal(t, sbom.Edge_optionalDependency, edges["Vulkan"])
	require.Equal(t, sbom.Edge_optionalDependency, edges["CUDAToolkit"])
	_, _, edges = extract(t, &api.DecomposerOptions{IncludeDev: true, IncludeBuild: true})
	require.Len(t, edges, 14)

	// A version from the caller names the root.
	root, _, _ = extract(t, &api.DecomposerOptions{Version: "v2.0.0", CommitHash: "abc123"})
	require.Equal(t, "v2.0.0", root.GetVersion())
	require.Len(t, root.GetExternalReferences(), 1)
}

// TestFindCodeBases checks a project is found once, at its outermost
// CMakeLists.txt that declares one.
func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	for _, dir := range []string{
		fixture, fixture + "/src", fixture + "/tests", fixture + "/third_party/vendored", fixture + "/examples/standalone",
	} {
		index.Add(dir, listsFile)
	}
	index.Add(fixture+"/cmake", "helpers.cmake")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{fixture}, found)

	// A project alone in a subdirectory is one too.
	alone := code.PathIndex{}
	alone.Add(fixture+"/examples/standalone", listsFile)
	alone.Add(fixture+"/src", listsFile)
	found, err = New().FindCodeBases(&alone)
	require.NoError(t, err)
	require.Equal(t, []string{fixture + "/examples/standalone"}, found)
}

func TestHostedRepository(t *testing.T) {
	t.Parallel()
	for repository, expected := range map[string]string{
		"https://github.com/Google/FlatBuffers.git": "github google flatbuffers",
		"https://github.com/fmtlib/fmt":             "github fmtlib fmt",
		"https://gitlab.com/group/sub/project.git":  "gitlab group/sub project",
		"https://bitbucket.org/owner/repo":          "bitbucket owner repo",
		"https://example.com/owner/repo.git":        "",
		"https://github.com/onlyowner":              "",
		"git@github.com:owner/repo.git":             "",
		"":                                          "",
	} {
		purlType, owner, repo, ok := hostedRepository(repository)
		got := ""
		if ok {
			got = purlType + " " + owner + " " + repo
		}
		require.Equal(t, expected, got, repository)
	}
}

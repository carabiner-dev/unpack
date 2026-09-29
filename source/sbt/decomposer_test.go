// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const (
	testSnapshot = "testdata/snapshot.json"
	testCommit   = "0123456789abcdef0123456789abcdef01234567"
)

// rewriteSnapshot writes a copy of the test snapshot with the replacements
// applied, given as old, new pairs, and returns its path.
func rewriteSnapshot(t *testing.T, oldnew ...string) string {
	t.Helper()
	data, err := os.ReadFile(testSnapshot)
	require.NoError(t, err)
	data = []byte(strings.NewReplacer(oldnew...).Replace(string(data)))
	path := filepath.Join(t.TempDir(), "snapshot.json")
	require.NoError(t, os.WriteFile(path, data, 0o600)) //nolint:gosec // a temp dir
	return path
}

func extractSnapshot(t *testing.T, path string, opts *api.DecomposerOptions) *sbom.NodeList {
	t.Helper()
	nl, err := New(path).Extract(opts)
	require.NoError(t, err)
	return nl
}

func nodeByPurl(t *testing.T, nl *sbom.NodeList, p string) *sbom.Node {
	t.Helper()
	var found *sbom.Node
	for _, n := range nl.GetNodes() {
		if string(n.Purl()) == p {
			require.Nil(t, found, "more than one node with purl %s", p)
			found = n
		}
	}
	require.NotNil(t, found, "no node with purl %s", p)
	return found
}

func hasNodePurl(nl *sbom.NodeList, p string) bool {
	for _, n := range nl.GetNodes() {
		if string(n.Purl()) == p {
			return true
		}
	}
	return false
}

func hasEdge(nl *sbom.NodeList, t sbom.Edge_Type, from, to *sbom.Node) bool {
	for _, e := range nl.GetEdges() {
		if e.GetType() != t || e.GetFrom() != from.GetId() {
			continue
		}
		for _, id := range e.GetTo() {
			if id == to.GetId() {
				return true
			}
		}
	}
	return false
}

func TestExtract(t *testing.T) {
	t.Parallel()

	nl := extractSnapshot(t, testSnapshot, &api.DecomposerOptions{WorkDir: "testdata"})

	// The root is the repository at the commit, named after the GitHub
	// repository the snapshot was generated in, versioned by its tag.
	require.Len(t, nl.GetRootNodes(), 1)
	root := nl.GetRootNodes()[0]
	require.Equal(t, "demo", root.GetName())
	require.Equal(t, "v1.0.0", root.GetVersion())
	require.Equal(t, "pkg:github/example/demo@v1.0.0", string(root.Purl()))
	require.Len(t, root.GetExternalReferences(), 1)
	vcs := root.GetExternalReferences()[0]
	require.Equal(t, sbom.ExternalReference_VCS, vcs.GetType())
	require.Equal(t, "git+https://github.com/example/demo@"+testCommit, vcs.GetUrl())
	require.Equal(t, testCommit, vcs.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])

	// Every manifest is a module of the build the root depends on.
	core := nodeByPurl(t, nl, "pkg:maven/com.example/core_3@1.0.0")
	app := nodeByPurl(t, nl, "pkg:maven/com.example/app_3@1.0.0")
	require.Equal(t, "core_3", core.GetName())
	require.Equal(t, "1.0.0", core.GetVersion())
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, core))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, app))

	// A module depending on another is linked to that module's node.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, app, core))

	// Libraries are shared across manifests, and the resolved tree hangs
	// from the direct dependencies.
	lib3 := nodeByPurl(t, nl, "pkg:maven/org.scala-lang/scala3-library_3@3.3.4")
	lib2 := nodeByPurl(t, nl, "pkg:maven/org.scala-lang/scala-library@2.13.14")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, core, lib3))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, lib3, lib2))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, app, lib3), "scala3-library is indirect in app")

	// Purls keep their qualifiers.
	jline := nodeByPurl(t, nl, "pkg:maven/org.jline/jline@3.26.3?packaging=jdk8")
	require.Equal(t, "jline", jline.GetName())
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, core, jline))

	// What the walk cannot reach still belongs to the module.
	stray := nodeByPurl(t, nl, "pkg:maven/org.example/stray@1.0")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, core, stray))

	// Callers naming modules the manifest does not list are skipped.
	require.False(t, hasNodePurl(nl, "pkg:maven/org.gone/evicted@0.1"))

	// Development modules are left out unless asked for.
	require.False(t, hasNodePurl(nl, "pkg:maven/org.scalameta/munit_3@1.0.0"))
	require.False(t, hasNodePurl(nl, "pkg:maven/junit/junit@4.13.2"))

	require.Len(t, nl.GetNodes(), 7)
}

func TestExtractIncludeDev(t *testing.T) {
	t.Parallel()

	nl := extractSnapshot(t, testSnapshot, &api.DecomposerOptions{WorkDir: "testdata", IncludeDev: true})

	core := nodeByPurl(t, nl, "pkg:maven/com.example/core_3@1.0.0")
	munit := nodeByPurl(t, nl, "pkg:maven/org.scalameta/munit_3@1.0.0")
	junit := nodeByPurl(t, nl, "pkg:maven/junit/junit@4.13.2")
	lib3 := nodeByPurl(t, nl, "pkg:maven/org.scala-lang/scala3-library_3@3.3.4")

	require.True(t, hasEdge(nl, sbom.Edge_devDependency, core, munit))
	require.True(t, hasEdge(nl, sbom.Edge_devDependency, munit, junit))
	// The edge type is the scope of the module depended on: munit needs
	// the library at runtime.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, munit, lib3))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, core, munit))

	require.Len(t, nl.GetNodes(), 9)
}

func TestExtractRoot(t *testing.T) {
	t.Parallel()

	t.Run("codebase-agrees", func(t *testing.T) {
		t.Parallel()
		nl := extractSnapshot(t, testSnapshot, &api.DecomposerOptions{
			WorkDir: "testdata", CommitHash: strings.ToUpper(testCommit), Version: "v1.0.0-2+abcdef01",
		})
		root := nl.GetRootNodes()[0]
		// The version read from git wins over the snapshot's ref.
		require.Equal(t, "v1.0.0-2+abcdef01", root.GetVersion())
		require.Equal(t, "pkg:github/example/demo@v1.0.0-2%2Babcdef01", string(root.Purl()))
	})

	t.Run("codebase-disagrees", func(t *testing.T) {
		t.Parallel()
		_, err := New(testSnapshot).Extract(&api.DecomposerOptions{
			WorkDir: "testdata", CommitHash: "ffffffffffffffffffffffffffffffffffffffff",
		})
		require.ErrorContains(t, err, "dependency snapshot was taken at commit "+testCommit)
	})

	t.Run("outside-github", func(t *testing.T) {
		t.Parallel()
		path := rewriteSnapshot(t,
			"https://github.com/example/demo/actions/runs/42", "https://ghe.example.com/example/demo/actions/runs/42",
			"refs/tags/v1.0.0", "refs/heads/main",
		)

		nl := extractSnapshot(t, path, &api.DecomposerOptions{WorkDir: "testdata"})
		root := nl.GetRootNodes()[0]
		// The directory lends its name, a branch is no version, and the
		// commit is still recorded.
		require.Equal(t, "testdata", root.GetName())
		require.Empty(t, root.GetVersion())
		require.Equal(t, "pkg:generic/testdata", string(root.Purl()))
		require.Equal(t, testCommit, root.GetExternalReferences()[0].GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
		require.Empty(t, root.GetExternalReferences()[0].GetUrl())
	})
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()

	index := &code.PathIndex{}
	index.Add("repo", "build.sbt")
	index.Add("repo/project", "build.properties")
	index.Add("repo/sbt-test/scripted/simple", "build.sbt")
	index.Add("repo/docs", "Gemfile.lock")

	t.Run("root-build", func(t *testing.T) {
		t.Parallel()
		locations, err := New(testSnapshot).FindCodeBases(index)
		require.NoError(t, err)
		require.Equal(t, []string{"repo"}, locations)
	})

	t.Run("nested-build", func(t *testing.T) {
		t.Parallel()
		path := rewriteSnapshot(t, `"source_location": "build.sbt"`, `"source_location": "scripted/simple/build.sbt"`)

		locations, err := New(path).FindCodeBases(index)
		require.NoError(t, err)
		require.Equal(t, []string{"repo/sbt-test/scripted/simple"}, locations)
	})

	t.Run("no-snapshot", func(t *testing.T) {
		t.Parallel()
		_, err := New("").FindCodeBases(index)
		require.Error(t, err)
	})
}

func TestParseSnapshot(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		data string
		err  string
	}{
		{"not-json", `{`, "decoding"},
		{"unknown-version", `{"version": 1, "manifests": {"a:b:1": {"resolved": {}}}}`, "unsupported dependency snapshot version 1"},
		{"no-manifests", `{"version": 0, "manifests": {}}`, "no manifests"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSnapshot(strings.NewReader(tc.data))
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestParseModuleRef(t *testing.T) {
	t.Parallel()

	org, name, version, ok := parseModuleRef("org.scala-lang:scala3-compiler_3:3.9.0")
	require.True(t, ok)
	require.Equal(t, []string{"org.scala-lang", "scala3-compiler_3", "3.9.0"}, []string{org, name, version})

	for _, ref := range []string{"scala3-compiler_3", "org::1.0"} {
		_, _, _, ok := parseModuleRef(ref)
		require.False(t, ok, ref)
	}
}

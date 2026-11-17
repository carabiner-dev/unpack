// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestModuleSetFromGoMod(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	t.Run("simple", func(t *testing.T) {
		t.Parallel()
		modFile, err := d.parseLocalGoMod("testdata/simple/go.mod")
		require.NoError(t, err)

		set := d.moduleSetFromGoMod(modFile, "testdata/simple/go.mod")
		assert.Equal(t, "example.com/simple", set.Main.Path)
		assert.Equal(t, "1.21", set.GoVersion)

		// Requirements carry the go.sum checksums.
		require.Len(t, set.Requires, 2)
		for _, m := range set.Requires {
			assert.NotEmpty(t, m.Sums, "%s should carry its go.sum hash", m.Key())
		}

		// Every requirement is in the module set, and the set is deduplicated.
		keys := map[string]int{}
		for _, m := range set.Modules {
			keys[m.Key()]++
		}
		for _, m := range set.Requires {
			assert.Equal(t, 1, keys[m.Key()])
		}
		for key, n := range keys {
			assert.Equal(t, 1, n, "%s listed more than once", key)
		}
	})

	t.Run("with-replace", func(t *testing.T) {
		t.Parallel()
		modFile, err := d.parseLocalGoMod("testdata/with-replace/go.mod")
		require.NoError(t, err)

		set := d.moduleSetFromGoMod(modFile, "testdata/with-replace/go.mod")
		require.Contains(t, set.Replaces, "github.com/old/module")
		assert.Equal(t, Replacement{Path: "github.com/new/module", Version: "v1.1.0"}, set.Replaces["github.com/old/module"])

		// The requirement is recorded as the module actually built.
		reqKeys := make([]string, 0, len(set.Requires))
		for _, m := range set.Requires {
			reqKeys = append(reqKeys, m.Key())
		}
		assert.Contains(t, reqKeys, "github.com/new/module@v1.1.0")
		assert.NotContains(t, reqKeys, "github.com/old/module@v1.0.0")
	})

	t.Run("no-go-sum", func(t *testing.T) {
		t.Parallel()
		modFile, err := d.parseLocalGoMod("testdata/simple/go.mod")
		require.NoError(t, err)

		// Pointing at a go.mod with no go.sum beside it yields a set built
		// from the requirements alone, with no checksums.
		set := d.moduleSetFromGoMod(modFile, "testdata/nonexistent/go.mod")
		require.Len(t, set.Requires, 2)
		assert.Len(t, set.Modules, 2)
		for _, m := range set.Modules {
			assert.Empty(t, m.Sums)
		}
	})
}

// TestModuleSetSplitsIndirect checks that requirements marked "// indirect"
// are kept apart from the direct ones, which alone become root edges.
func TestModuleSetSplitsIndirect(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	dir := t.TempDir()
	goModPath := filepath.Join(dir, "go.mod")
	require.NoError(t, os.WriteFile(goModPath, []byte(`module example.com/app

go 1.21

require example.com/direct v1.0.0

require (
	example.com/reached v1.1.0 // indirect
	example.com/orphan v1.2.0 // indirect
)
`), 0o600))

	modFile, err := d.parseLocalGoMod(goModPath)
	require.NoError(t, err)
	set := d.moduleSetFromGoMod(modFile, goModPath)

	assert.Equal(t, []Module{{Path: "example.com/direct", Version: "v1.0.0"}}, set.Requires)
	assert.Equal(t, []Module{
		{Path: "example.com/reached", Version: "v1.1.0"},
		{Path: "example.com/orphan", Version: "v1.2.0"},
	}, set.Indirect)
	assert.Len(t, set.Modules, 3, "indirect requirements are part of the set")
}

// TestModuleSetGoSumExtras checks which go.sum entries join the set: none
// when go.mod lists the whole build and, when it is too old to, the
// highest version of each path it does not require, if it was downloaded.
func TestModuleSetGoSumExtras(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	const goSum = `example.com/dep v1.0.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/dep v1.5.0 h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/dep v1.5.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/dep v1.9.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/testonly v0.1.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/transitive v0.9.0 h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/transitive v0.9.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/transitive v0.10.0 h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/transitive v0.10.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/transitive v0.2.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/another v1.0.0 h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
example.com/another v1.1.0/go.mod h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
`
	// go.mod's version of dep stands, whatever go.sum lists. transitive
	// is taken at its highest version, compared as versions and not as
	// text. testonly was never downloaded, and neither was the version
	// of another that the graph selects.
	fromGoSum := []string{"example.com/dep@v1.5.0", "example.com/transitive@v0.10.0"}

	for _, tc := range []struct {
		name      string
		goVersion string
		want      []string
	}{
		{"complete", "go 1.17", []string{"example.com/dep@v1.5.0"}},
		{"complete-patch", "go 1.26.0", []string{"example.com/dep@v1.5.0"}},
		{"old", "go 1.16", fromGoSum},
		{"undeclared", "", fromGoSum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			goModPath := filepath.Join(dir, "go.mod")
			goMod := "module example.com/app\n\n" + tc.goVersion + "\n\nrequire example.com/dep v1.5.0\n"
			require.NoError(t, os.WriteFile(goModPath, []byte(goMod), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o600))

			modFile, err := d.parseLocalGoMod(goModPath)
			require.NoError(t, err)
			set := d.moduleSetFromGoMod(modFile, goModPath)

			keys := make([]string, 0, len(set.Modules))
			for _, m := range set.Modules {
				keys = append(keys, m.Key())
			}
			assert.Equal(t, tc.want, keys)
			assert.NotEmpty(t, set.Modules[0].Sums, "the requirement keeps its go.sum checksum")
		})
	}
}

func TestAttachUnreached(t *testing.T) {
	t.Parallel()

	const root = "example.com/app"
	trees := map[string][]string{
		root:                        {"example.com/direct@v1.0.0"},
		"example.com/direct@v1.0.0": {"example.com/reached@v1.1.0"},
		// The orphan brings a module of its own, and sits in a cycle
		// with it.
		"example.com/orphan@v1.2.0": {"example.com/under@v1.3.0"},
		"example.com/under@v1.3.0":  {"example.com/orphan@v1.2.0"},
	}

	attachUnreached(trees, root, []Module{
		{Path: "example.com/reached", Version: "v1.1.0"},
		{Path: "example.com/orphan", Version: "v1.2.0"},
		{Path: "example.com/under", Version: "v1.3.0"},
	})

	assert.Equal(t,
		[]string{"example.com/direct@v1.0.0", "example.com/orphan@v1.2.0"},
		trees[root],
		"only the module no edge reaches is attached to the root",
	)
}

// TestBuildNodeListFromSet renders a module set assembled by hand, with no
// go.mod anywhere, the way a binary's build info would be. Networking is off
// so the graph is exactly the set's own edges.
func TestBuildNodeListFromSet(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	set := &ModuleSet{
		Main:      Module{Path: "example.com/app", Version: "v1.2.3"},
		GoVersion: "1.24.0",
		Requires: []Module{
			{Path: "example.com/lib", Version: "v0.1.0"},
			{
				Path: "example.com/hashed", Version: "v2.0.0",
				Sums: []string{"h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
			},
		},
	}
	set.Modules = append(set.Modules, set.Requires...)
	// A module in the set that nothing requires is not emitted.
	set.Modules = append(set.Modules, Module{Path: "example.com/orphan", Version: "v9.0.0"})

	nl, err := d.BuildNodeList(set, &api.DecomposerOptions{
		Version:    "v1.2.3",
		Networking: api.NetworkDisabled,
	})
	require.NoError(t, err)

	roots := nl.GetRootElements()
	require.Len(t, roots, 1)
	root := nl.GetNodeByID(roots[0])
	require.NotNil(t, root)
	assert.Equal(t, "pkg:golang/example.com/app@v1.2.3", root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	byPurl := func(purl string) *sbom.Node {
		nodes := nl.GetNodesByIdentifier("purl", purl)
		if len(nodes) == 0 {
			return nil
		}
		return nodes[0]
	}

	// Requirements hang off the root.
	lib := byPurl("pkg:golang/example.com/lib@v0.1.0")
	require.NotNil(t, lib)
	hashed := byPurl("pkg:golang/example.com/hashed@v2.0.0")
	require.NotNil(t, hashed)
	assert.Equal(t,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		hashed.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
		"h1: sums are decoded to hex SHA-256",
	)

	// The stdlib node comes from GoVersion.
	stdlib := byPurl("pkg:golang/stdlib@1.24.0")
	require.NotNil(t, stdlib)

	// Nothing reaches the orphan, so it is not in the graph.
	assert.Nil(t, byPurl("pkg:golang/example.com/orphan@v9.0.0"))

	// All edges originate at the root and are dependsOn.
	for _, e := range nl.GetEdges() {
		assert.Equal(t, root.GetId(), e.GetFrom())
		assert.Equal(t, sbom.Edge_dependsOn, e.GetType())
	}
	assert.Len(t, nl.GetEdges(), 1, "protobom groups one edge per source node")

	// Missing main module is rejected.
	_, err = d.BuildNodeList(&ModuleSet{}, nil)
	require.Error(t, err)
}

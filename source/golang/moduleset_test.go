// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
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

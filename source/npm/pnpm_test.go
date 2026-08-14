// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

// extractPnpm runs the decomposer over a pnpm testdata codebase.
func extractPnpmTree(t *testing.T, testdata string, opts *api.DecomposerOptions) *sbom.NodeList {
	t.Helper()
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}
	opts.WorkDir = "testdata/" + testdata
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	return nl
}

func pnpmNodeNamed(t *testing.T, nl *sbom.NodeList, name string) *sbom.Node {
	t.Helper()
	var found *sbom.Node
	for _, n := range nl.GetNodes() {
		if n.GetName() == name {
			require.Nil(t, found, "more than one node named %s", name)
			found = n
		}
	}
	require.NotNil(t, found, "no node named %s", name)
	return found
}

func pnpmHasEdge(nl *sbom.NodeList, edgeType sbom.Edge_Type, from, to *sbom.Node) bool {
	for _, e := range nl.GetEdges() {
		if e.GetType() == edgeType && e.GetFrom() == from.GetId() {
			for _, id := range e.GetTo() {
				if id == to.GetId() {
					return true
				}
			}
		}
	}
	return false
}

// TestExtractPnpm reads the lock pnpm 11 writes (schema 9) and
// TestExtractPnpm6 the one pnpm 8 writes (schema 6): the same project,
// the same expectations, two spellings.
func TestExtractPnpm(t *testing.T) {
	t.Parallel()
	for name, testdata := range map[string]string{
		"schema 9": "pnpm",
		"schema 6": "pnpm6",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nl := extractPnpmTree(t, testdata, nil)

			// The project roots the graph with its manifest's identity.
			root := pnpmNodeNamed(t, nl, "jsdemo")
			require.Equal(t, []string{root.GetId()}, nl.GetRootElements())
			require.Equal(t, "0.1.0", root.GetVersion())

			// Runtime dependencies and their edges: debug pulls in ms.
			debug := pnpmNodeNamed(t, nl, "debug")
			ms := pnpmNodeNamed(t, nl, "ms")
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, root, debug))
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, root, ms))
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, debug, ms))

			// Neither the dev nor the optional sections were asked for.
			for _, n := range nl.GetNodes() {
				require.NotEqual(t, "once", n.GetName())
				require.NotEqual(t, "wrappy", n.GetName())
			}

			// The lock's SRI integrity becomes the node's hash, in hex.
			hash := debug.GetHashes()[int32(sbom.HashAlgorithm_SHA512)]
			require.Len(t, hash, 128)
			require.Equal(t, "pkg:npm/debug@"+debug.GetVersion(),
				debug.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
		})
	}
}

func TestExtractPnpmDevAndOptional(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true}
	nl := extractPnpmTree(t, "pnpm", opts)

	root := pnpmNodeNamed(t, nl, "jsdemo")
	once := pnpmNodeNamed(t, nl, "once")
	wrappy := pnpmNodeNamed(t, nl, "wrappy")

	require.True(t, pnpmHasEdge(nl, sbom.Edge_devDependency, root, once))
	require.True(t, pnpmHasEdge(nl, sbom.Edge_optionalDependency, root, wrappy))

	// The dev dependency's own runtime needs came with it, as plain
	// dependencies of it.
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, once, wrappy))
}

// TestExtractPnpmWorkspace reads a workspace lock: every importer roots
// the graph, and a workspace:* dependency is an edge between importers.
func TestExtractPnpmWorkspace(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true}
	nl := extractPnpmTree(t, "pnpmws", opts)

	require.Len(t, nl.GetRootElements(), 2)
	root := pnpmNodeNamed(t, nl, "jsws")
	liba := pnpmNodeNamed(t, nl, "liba")
	require.Contains(t, nl.GetRootElements(), root.GetId())
	require.Contains(t, nl.GetRootElements(), liba.GetId())

	// The member keeps its own manifest's identity,
	require.Equal(t, "0.2.0", liba.GetVersion())

	// the link: dependency is an edge from the project to the member,
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, root, liba))

	// and the member's own dependencies hang under it.
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, liba, pnpmNodeNamed(t, nl, "wrappy")))
}

// TestFindCodeBasesLockfiles pins the discovery rules: both lockfiles are
// codebases, and anything under node_modules is not. The node_modules
// filter used to compare against a literal "%snode_modules%s", so it never
// filtered anything.
func TestFindCodeBasesLockfiles(t *testing.T) {
	t.Parallel()

	index := code.PathIndex{}
	index.Add("app", "package-lock.json")
	index.Add("tool", "pnpm-lock.yaml")
	index.Add("app/node_modules/dep", "package-lock.json")
	index.Add("app/node_modules/other", "pnpm-lock.yaml")

	locations, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"app", "tool"}, locations)
}

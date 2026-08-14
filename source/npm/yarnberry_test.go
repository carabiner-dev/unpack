// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestExtractYarnBerry(t *testing.T) {
	t.Parallel()

	nl := extractPnpmTree(t, "yarnberry", nil)

	// The workspace's identity comes from its manifest: the lock says
	// 0.0.0-use.local.
	root := pnpmNodeNamed(t, nl, "jsdemo")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())
	require.Equal(t, "0.1.0", root.GetVersion())

	// Runtime edges resolve through the protocol-carrying selectors.
	debug := pnpmNodeNamed(t, nl, "debug")
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, root, debug))
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, debug, pnpmNodeNamed(t, nl, "ms")))

	// The scoped package, from its quoted selector.
	scoped := pnpmNodeNamed(t, nl, "@tootallnate/once")
	require.Equal(t, "2.0.1", scoped.GetVersion())

	// The lock flattens dev dependencies into the workspace block; the
	// manifest tells them apart, and dev was not asked for.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "once", n.GetName())
	}

	// No hashes, deliberately: berry's checksum covers its own cache
	// archive, not the registry tarball, and a hash nothing else can
	// reproduce identifies nothing.
	require.Empty(t, debug.GetHashes())
	require.Empty(t, debug.GetUrlDownload())
}

func TestExtractYarnBerryDevAndOptional(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true}
	nl := extractPnpmTree(t, "yarnberry", opts)

	root := pnpmNodeNamed(t, nl, "jsdemo")
	require.True(t, pnpmHasEdge(nl, sbom.Edge_devDependency, root, pnpmNodeNamed(t, nl, "once")))
	require.True(t, pnpmHasEdge(nl, sbom.Edge_optionalDependency, root, pnpmNodeNamed(t, nl, "wrappy")))
}

// TestExtractYarnBerryWorkspace covers the workspace form: every member an
// entry of the lock, cross-dependencies as workspace: references resolved
// through the same selector map as everything else.
func TestExtractYarnBerryWorkspace(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true}
	nl := extractPnpmTree(t, "yarnberryws", opts)

	require.Len(t, nl.GetRootElements(), 2)
	root := pnpmNodeNamed(t, nl, "jsws")
	liba := pnpmNodeNamed(t, nl, "liba")
	require.Contains(t, nl.GetRootElements(), root.GetId())
	require.Contains(t, nl.GetRootElements(), liba.GetId())

	// The member's manifest supplies its version,
	require.Equal(t, "0.2.0", liba.GetVersion())

	// the workspace:* dependency is an edge between the two,
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, root, liba))

	// and the member's own dependencies hang under it.
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, liba, pnpmNodeNamed(t, nl, "wrappy")))
}

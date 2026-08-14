// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"os"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestExtractYarn(t *testing.T) {
	t.Parallel()

	nl := extractPnpmTree(t, "yarn", nil)

	// The manifest supplies the root: the lock does not know the project.
	root := pnpmNodeNamed(t, nl, "jsdemo")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())
	require.Equal(t, "0.1.0", root.GetVersion())

	// Runtime edges, the transitive one resolved through a selector the
	// block shares with another range: once requires wrappy@1, the
	// manifest wrappy@^1.0.2, one resolution.
	debug := pnpmNodeNamed(t, nl, "debug")
	ms := pnpmNodeNamed(t, nl, "ms")
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, root, debug))
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, debug, ms))

	// The scoped package parsed out of its quoted selector.
	scoped := pnpmNodeNamed(t, nl, "@tootallnate/once")
	require.Equal(t, "2.0.1", scoped.GetVersion())
	require.Equal(t, "pkg:npm/tootallnate/once@2.0.1",
		scoped.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	// The lock's integrity and resolved URL carry over.
	require.Len(t, debug.GetHashes()[int32(sbom.HashAlgorithm_SHA512)], 128)
	require.Contains(t, debug.GetUrlDownload(), "registry.yarnpkg.com/debug")

	// Dev and optional were not asked for.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "once", n.GetName())
	}
}

func TestExtractYarnDevAndOptional(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true}
	nl := extractPnpmTree(t, "yarn", opts)

	root := pnpmNodeNamed(t, nl, "jsdemo")
	once := pnpmNodeNamed(t, nl, "once")
	wrappy := pnpmNodeNamed(t, nl, "wrappy")

	// The kinds come from the manifest, since the lock records none.
	require.True(t, pnpmHasEdge(nl, sbom.Edge_devDependency, root, once))
	require.True(t, pnpmHasEdge(nl, sbom.Edge_optionalDependency, root, wrappy))
	require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, once, wrappy))

	// wrappy@1 (from once) and wrappy@^1.0.2 (from the manifest) resolve
	// to one package and one node.
	require.Equal(t, "1.0.2", wrappy.GetVersion())
}

// TestYarnBerryRefused pins the sniff: both yarn generations call their
// file yarn.lock, and reading a berry lock as classic would yield
// garbage, so it is refused by name until the berry reader exists.
func TestYarnBerryRefused(t *testing.T) {
	t.Parallel()

	berry := []byte("# comment\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n")
	require.True(t, IsYarnBerry(berry))
	_, err := ParseYarnLock(berry)
	require.ErrorContains(t, err, "berry")

	classic, err := os.ReadFile("testdata/yarn/yarn.lock")
	require.NoError(t, err)
	require.False(t, IsYarnBerry(classic))
}

// TestExtractDispatchOrder pins the lockfile precedence when a codebase
// holds several: npm's own, then pnpm, then yarn.
func TestExtractDispatchOrder(t *testing.T) {
	t.Parallel()

	read := func(t *testing.T, path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return data
	}
	write := func(t *testing.T, dir, name string, data []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(dir+"/"+name, data, 0o600))
	}

	// pnpm and yarn locks side by side: pnpm wins. The two fixtures name
	// their roots differently only through package.json, so the winning
	// lock is told by which package.json parses cleanly with it — use the
	// pnpm fixture's manifest.
	dir := t.TempDir()
	write(t, dir, "package.json", read(t, "testdata/pnpm/package.json"))
	write(t, dir, "pnpm-lock.yaml", read(t, "testdata/pnpm/pnpm-lock.yaml"))
	write(t, dir, "yarn.lock", []byte("__metadata:\n  version: 8\n"))

	opts := &api.DecomposerOptions{WorkDir: dir}
	nl, err := New().Extract(opts)
	require.NoError(t, err, "the berry yarn.lock must not have been chosen")
	require.NotEmpty(t, nl.GetNodes())

	// A directory with no lockfile at all is not a codebase.
	opts = &api.DecomposerOptions{WorkDir: t.TempDir()}
	_, err = New().Extract(opts)
	require.ErrorContains(t, err, "no supported JavaScript lockfile")
}

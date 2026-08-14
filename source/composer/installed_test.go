// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"os"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// The fixtures are one real installed.json, written by composer install
// over the simple testdata project, in two placements: app/ has the
// project's composer.json above its vendor directory, bare/ has only the
// vendor directory.

func extractInstalledFS(t *testing.T, dir string, opts *api.DecomposerOptions) *sbom.NodeList {
	t.Helper()
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}
	nl, err := ExtractInstalled(os.DirFS(dir), opts)
	require.NoError(t, err)
	require.NotNil(t, nl)
	return nl
}

// TestExtractInstalledWithManifest covers the placement deployments have:
// the manifest above the vendor directory supplies the root, and the
// installed environment reads exactly like a lock found in place.
func TestExtractInstalledWithManifest(t *testing.T) {
	t.Parallel()

	nl := extractInstalledFS(t, "testdata/installed/app", nil)

	root := nodeNamed(t, nl, "carabiner/phpdemo")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())

	monolog := nodeNamed(t, nl, "monolog/monolog")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, monolog))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, monolog, nodeNamed(t, nl, "psr/log")))

	// Licenses offline, from the installed metadata.
	require.Equal(t, []string{"MIT"}, monolog.GetLicenses())

	// The dev partition stays out until asked for,
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "psr/container", n.GetName())
	}

	// and arrives as the manifest's dev requirement when it is.
	opts := &api.DecomposerOptions{IncludeDev: true}
	nl = extractInstalledFS(t, "testdata/installed/app", opts)
	require.True(t, hasEdge(nl, sbom.Edge_devDependency,
		nodeNamed(t, nl, "carabiner/phpdemo"), nodeNamed(t, nl, "psr/container")))
}

// TestExtractInstalledBare covers a vendor directory with no manifest
// above it: the graph's own shape supplies the roots.
func TestExtractInstalledBare(t *testing.T) {
	t.Parallel()

	nl := extractInstalledFS(t, "testdata/installed/bare", nil)

	// Nothing installed requires monolog, so it roots the graph; psr/log
	// hangs under it.
	monolog := nodeNamed(t, nl, "monolog/monolog")
	require.Equal(t, []string{monolog.GetId()}, nl.GetRootElements())
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, monolog, nodeNamed(t, nl, "psr/log")))

	// The dev partition, told by installed.json's dev-package-names,
	// stays out by default and roots itself when included.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "psr/container", n.GetName())
	}
	nl = extractInstalledFS(t, "testdata/installed/bare", &api.DecomposerOptions{IncludeDev: true})
	container := nodeNamed(t, nl, "psr/container")
	require.Contains(t, nl.GetRootElements(), container.GetId())
}

// TestExtractInstalledMerges covers a filesystem holding several vendor
// directories — an image with more than one PHP application — merged into
// one graph.
func TestExtractInstalledMerges(t *testing.T) {
	t.Parallel()

	nl := extractInstalledFS(t, "testdata/installed", nil)

	// Both environments are here: the app's root and the bare tree's
	// in-degree-zero root.
	nodeNamed(t, nl, "carabiner/phpdemo")
	require.Len(t, nl.GetRootElements(), 2)

	// Both hold monolog; each keeps its own node.
	count := 0
	for _, n := range nl.GetNodes() {
		if n.GetName() == "monolog/monolog" {
			count++
		}
	}
	require.Equal(t, 2, count)
}

// TestParseInstalledJSONComposer1 covers the previous generation's shape:
// the bare package array, with no dev partition to speak of.
func TestParseInstalledJSONComposer1(t *testing.T) {
	t.Parallel()

	lock, err := ParseInstalledJSON([]byte(`[
		{"name": "monolog/monolog", "version": "1.27.1", "require": {"php": ">=5.3.0", "psr/log": "~1.0"}},
		{"name": "psr/log", "version": "1.1.4"}
	]`))
	require.NoError(t, err)
	require.Len(t, lock.Packages, 2)
	require.Empty(t, lock.PackagesDev)

	_, err = ParseInstalledJSON([]byte(`{"not": "installed.json"}`))
	require.Error(t, err)
}

// TestExtractInstalledNone pins the shared system contract: no Composer on
// the filesystem reads as nothing, not as an error.
func TestExtractInstalledNone(t *testing.T) {
	t.Parallel()

	nl, err := ExtractInstalled(os.DirFS("testdata/simple"), &api.DecomposerOptions{})
	require.NoError(t, err)
	require.Nil(t, nl)
}

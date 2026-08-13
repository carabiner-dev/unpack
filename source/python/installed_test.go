// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"os"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func installedTestGraph(t *testing.T, includeFiles bool) *sbom.NodeList {
	t.Helper()
	dists, err := FindDistributions(os.DirFS("testdata/sitepackages"))
	require.NoError(t, err)
	nl, err := InstalledNodeList(dists, includeFiles)
	require.NoError(t, err)
	return nl
}

func TestInstalledNodeList(t *testing.T) {
	t.Parallel()

	nl := installedTestGraph(t, false)
	require.Len(t, nl.GetNodes(), 7)

	// uv pip install --target stamps every package REQUESTED, so the
	// marker tells nothing apart here and the graph's shape decides:
	// whatever nothing depends on is a root.
	roots := map[string]bool{}
	for _, id := range nl.GetRootElements() {
		for _, n := range nl.GetNodes() {
			if n.GetId() == id {
				roots[n.GetName()] = true
			}
		}
	}
	require.Equal(t, map[string]bool{"requests": true, "python-dotenv": true}, roots)

	// The declared dependencies whose targets are installed are edges.
	requests := nodeNamed(t, nl, "requests")
	for _, dep := range []string{"certifi", "charset-normalizer", "idna", "urllib3"} {
		require.True(t, hasEdge(nl, sbom.Edge_dependsOn, requests, nodeNamed(t, nl, dep)),
			"requests should depend on %s", dep)
	}

	// pysocks is declared behind the socks extra, and it is installed:
	// an optional dependency in fact.
	require.True(t, hasEdge(nl, sbom.Edge_optionalDependency, requests, nodeNamed(t, nl, "pysocks")))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, requests, nodeNamed(t, nl, "pysocks")))

	// Licences come from the installed metadata: offline, all three tiers.
	require.Equal(t, []string{"Apache-2.0"}, requests.GetLicenses())
	require.Equal(t, []string{"BSD-3-Clause"}, nodeNamed(t, nl, "idna").GetLicenses())

	// The git install carries its provenance down to the commit.
	dotenv := nodeNamed(t, nl, "python-dotenv")
	require.Equal(t,
		"https://github.com/theskumar/python-dotenv#eaf2a9129ccec6febda0f741eb3bb852c3f947bd",
		dotenv.GetUrlDownload())

	// And the installer is on record.
	sawInstaller := false
	for _, prop := range requests.GetProperties() {
		if prop.GetName() == "python:installer" {
			require.Equal(t, "uv", prop.GetData())
			sawInstaller = true
		}
	}
	require.True(t, sawInstaller)

	// purls throughout.
	require.Equal(t, "pkg:pypi/requests@2.34.2",
		requests.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
}

func TestInstalledNodeListFiles(t *testing.T) {
	t.Parallel()

	// Without files: packages only.
	for _, n := range installedTestGraph(t, false).GetNodes() {
		require.Equal(t, sbom.Node_PACKAGE, n.GetType())
	}

	// With files: every RECORD entry, related to its package, hashes
	// respelled from RECORD's base64 into hex.
	nl := installedTestGraph(t, true)
	files := 0
	hexed := 0
	for _, n := range nl.GetNodes() {
		if n.GetType() != sbom.Node_FILE {
			continue
		}
		files++
		if hash := n.GetHashes()[int32(sbom.HashAlgorithm_SHA256)]; hash != "" {
			hexed++
			require.Len(t, hash, 64)
			require.NotContains(t, hash, "=")
		}
	}
	require.NotZero(t, files)
	require.NotZero(t, hexed)

	// A file hangs off its package.
	requests := nodeNamed(t, nl, "requests")
	related := false
	for _, e := range nl.GetEdges() {
		if e.GetType() == sbom.Edge_contains && e.GetFrom() == requests.GetId() {
			related = true
		}
	}
	require.True(t, related)
}

// TestInstalledRequestedRoots covers the REQUESTED marker doing its job:
// when it tells packages apart, it names the roots.
func TestInstalledRequestedRoots(t *testing.T) {
	t.Parallel()

	dists := []*InstalledDistribution{
		{Name: "app", Version: "1.0", Requested: true, RequiresDist: []string{"lib"}},
		{Name: "lib", Version: "2.0"},
	}
	nl, err := InstalledNodeList(dists, false)
	require.NoError(t, err)

	require.Len(t, nl.GetRootElements(), 1)
	app := nodeNamed(t, nl, "app")
	require.Equal(t, []string{app.GetId()}, nl.GetRootElements())
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, app, nodeNamed(t, nl, "lib")))
}

// TestInstalledMarkerClassification pins how a declaration's marker decides
// the edge type: extra-gated means optional, anything else installed means
// a plain dependency.
func TestInstalledMarkerClassification(t *testing.T) {
	t.Parallel()

	dists := []*InstalledDistribution{
		{Name: "app", Version: "1.0", Requested: true, RequiresDist: []string{
			`plain>=1`,
			`conditional>=1 ; python_version >= "3.8"`,
			`optional>=1 ; extra == "fast"`,
			`absent>=1`,
		}},
		{Name: "plain", Version: "1.0"},
		{Name: "conditional", Version: "1.0"},
		{Name: "optional", Version: "1.0"},
	}
	nl, err := InstalledNodeList(dists, false)
	require.NoError(t, err)

	app := nodeNamed(t, nl, "app")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, app, nodeNamed(t, nl, "plain")))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, app, nodeNamed(t, nl, "conditional")),
		"an installed conditional dependency held: it is here")
	require.True(t, hasEdge(nl, sbom.Edge_optionalDependency, app, nodeNamed(t, nl, "optional")))
	for _, n := range nl.GetNodes() {
		require.False(t, strings.HasPrefix(n.GetName(), "absent"),
			"a declaration whose target is not installed is nothing")
	}
}

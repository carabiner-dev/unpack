// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

func extractComposer(t *testing.T, testdata string, opts *api.DecomposerOptions) *sbom.NodeList {
	t.Helper()
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}
	opts.WorkDir = "testdata/" + testdata
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	return nl
}

func nodeNamed(t *testing.T, nl *sbom.NodeList, name string) *sbom.Node {
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

func hasEdge(nl *sbom.NodeList, edgeType sbom.Edge_Type, from, to *sbom.Node) bool {
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

func TestExtractComposer(t *testing.T) {
	t.Parallel()

	nl := extractComposer(t, "simple", nil)

	// The manifest supplies the root.
	root := nodeNamed(t, nl, "carabiner/phpdemo")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())
	require.Equal(t, []string{"Apache-2.0"}, root.GetLicenses())

	// The direct requirement and its transitive: monolog needs psr/log.
	monolog := nodeNamed(t, nl, "monolog/monolog")
	psrlog := nodeNamed(t, nl, "psr/log")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, monolog))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, monolog, psrlog))

	// The dev requirement stays out until asked for.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "psr/container", n.GetName())
	}

	// Everything is in the lock: license, description, homepage, archive
	// URL and the repository with its exact commit. No network happened.
	require.Equal(t, []string{"MIT"}, monolog.GetLicenses())
	require.NotEmpty(t, monolog.GetDescription())
	require.Contains(t, monolog.GetUrlHome(), "github.com/Seldaek/monolog")
	require.Contains(t, monolog.GetUrlDownload(), "zipball")
	require.Len(t, monolog.GetExternalReferences(), 1)
	ref := monolog.GetExternalReferences()[0]
	require.Equal(t, sbom.ExternalReference_VCS, ref.GetType())
	require.Contains(t, ref.GetUrl(), "github.com/Seldaek/monolog.git#")

	// The vendor is the purl namespace.
	require.Equal(t, "pkg:composer/monolog/monolog@"+monolog.GetVersion(),
		monolog.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	// Platform requirements — php itself — became nothing.
	for _, n := range nl.GetNodes() {
		require.Contains(t, n.GetName(), "/")
	}
}

func TestExtractComposerDev(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true}
	nl := extractComposer(t, "simple", opts)

	root := nodeNamed(t, nl, "carabiner/phpdemo")
	container := nodeNamed(t, nl, "psr/container")
	require.True(t, hasEdge(nl, sbom.Edge_devDependency, root, container))
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()

	index := code.PathIndex{}
	index.Add("app", "composer.lock")
	index.Add("other", "package-lock.json")
	locations, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"app"}, locations)
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"os"
	"path/filepath"
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

// TestExtractComposerSuppliers checks a package is supplied by the authors
// its lock entry lists, in order, each with what the lock says of it. An
// entry without a name names nobody, and a package listing no authors has
// no supplier.
func TestExtractComposerSuppliers(t *testing.T) {
	t.Parallel()

	// The fixture's own lock, written by Composer.
	nl := extractComposer(t, "simple", nil)
	monolog := nodeNamed(t, nl, "monolog/monolog")
	require.Len(t, monolog.GetSuppliers(), 1)
	require.Equal(t, "Jordi Boggiano", monolog.GetSuppliers()[0].GetName())
	require.Equal(t, "j.boggiano@seld.be", monolog.GetSuppliers()[0].GetEmail())
	require.Equal(t, "https://seld.be", monolog.GetSuppliers()[0].GetUrl())

	psrLog := nodeNamed(t, nl, "psr/log")
	require.Len(t, psrLog.GetSuppliers(), 1)
	require.Equal(t, "PHP-FIG", psrLog.GetSuppliers()[0].GetName())
	require.Empty(t, psrLog.GetSuppliers()[0].GetEmail())

	// The project is not a package of the lock: its supplier is for
	// whoever produces the document to state.
	require.Empty(t, nodeNamed(t, nl, "carabiner/phpdemo").GetSuppliers())

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.json"), []byte(
		`{"name": "acme/app", "require": {"acme/several": "^1.0", "acme/none": "^1.0"}}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{
    "content-hash": "abc",
    "packages": [
        {"name": "acme/none", "version": "1.0.0"},
        {
            "name": "acme/several",
            "version": "1.0.0",
            "authors": [
                {"name": "First Author", "email": "first@example.com"},
                {"email": "nameless@example.com"},
                {"name": "Second Author"}
            ]
        }
    ],
    "packages-dev": []
}`), 0o600))

	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: dir, Networking: api.NetworkDisabled})
	require.NoError(t, err)

	several := nodeNamed(t, nl, "acme/several").GetSuppliers()
	require.Len(t, several, 2)
	require.Equal(t, "First Author", several[0].GetName())
	require.Equal(t, "Second Author", several[1].GetName())
	require.Empty(t, nodeNamed(t, nl, "acme/none").GetSuppliers())
}

func TestExtractComposerDev(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{IncludeDev: true}
	nl := extractComposer(t, "simple", opts)

	root := nodeNamed(t, nl, "carabiner/phpdemo")
	container := nodeNamed(t, nl, "psr/container")
	require.True(t, hasEdge(nl, sbom.Edge_devDependency, root, container))
}

// TestExtractComposerStandIns reads a lock where requirements name what
// has no package of its own: components a framework replaces, a virtual
// package two packages provide, and a requirement nothing meets.
func TestExtractComposerStandIns(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{
    "name": "acme/app",
    "require": {
        "acme/component": "^5.0",
        "acme/framework": "^5.0",
        "acme/plugin": "^1.0"
    },
    "require-dev": {
        "acme/never-locked": "^1.0"
    }
}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{
    "content-hash": "abc",
    "packages": [
        {
            "name": "acme/framework",
            "version": "5.1.0",
            "require": {"php": ">=8.1", "acme/console": "self.version"},
            "replace": {"acme/component": "self.version", "acme/console": "self.version"}
        },
        {
            "name": "acme/logger-a",
            "version": "1.0.0",
            "provide": {"psr/log-implementation": "3.0.0"}
        },
        {
            "name": "acme/logger-b",
            "version": "2.0.0",
            "provide": {"psr/log-implementation": "3.0.0"}
        },
        {
            "name": "acme/plugin",
            "version": "1.2.0",
            "require": {"acme/component": "^5.0", "psr/log-implementation": "^3.0"}
        }
    ],
    "packages-dev": []
}`), 0o600))

	nl, err := New().Extract(&api.DecomposerOptions{
		WorkDir:    dir,
		IncludeDev: true,
		Networking: api.NetworkDisabled,
	})
	require.NoError(t, err)

	root := nodeNamed(t, nl, "acme/app")
	framework := nodeNamed(t, nl, "acme/framework")
	plugin := nodeNamed(t, nl, "acme/plugin")

	// A requirement on a replaced component is met by the framework,
	// from the root and from another package alike.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, framework))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, plugin))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, plugin, framework))

	// A virtual package is met by each package providing it.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, plugin, nodeNamed(t, nl, "acme/logger-a")))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, plugin, nodeNamed(t, nl, "acme/logger-b")))

	// The names stood in for are not packages, a package requiring what
	// it replaces itself gets no edge to itself, and the requirement
	// nothing meets is left out without failing the rest.
	require.Len(t, nl.GetNodes(), 5)
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, framework, framework))
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

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"os"
	"path/filepath"
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
		opts = &api.DecomposerOptions{Networking: api.NetworkDisabled}
	}
	opts.WorkDir = "testdata/" + testdata
	// The graph tests are about the lock, not the registry: the zero
	// networking value is NetworkEssential, which would quietly turn
	// every test into a registry client.
	opts.Networking = api.NetworkDisabled
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

	opts := &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true, Networking: api.NetworkDisabled}
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

	opts := &api.DecomposerOptions{IncludeDev: true, Networking: api.NetworkDisabled}
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

// pnpmPeerVariantsLock is a lock where plug is installed twice, once for
// each version of the peer it is resolved against, in the spelling of
// each schema generation.
var pnpmPeerVariantsLock = map[string]string{
	"schema 9": `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      x:
        specifier: ^1.0.0
        version: 1.0.0
      y:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  common@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}

  host@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}

  host@2.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}

  plug@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    peerDependencies:
      host: '*'

  x@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}

  y@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}

snapshots:

  common@1.0.0: {}

  host@1.0.0: {}

  host@2.0.0: {}

  plug@1.0.0(host@1.0.0):
    dependencies:
      common: 1.0.0
      host: 1.0.0

  plug@1.0.0(host@2.0.0):
    dependencies:
      common: 1.0.0
      host: 2.0.0

  x@1.0.0:
    dependencies:
      host: 1.0.0
      plug: 1.0.0(host@1.0.0)

  y@1.0.0:
    dependencies:
      host: 2.0.0
      plug: 1.0.0(host@2.0.0)
`,
	"schema 6": `lockfileVersion: '6.0'

dependencies:
  x:
    specifier: ^1.0.0
    version: 1.0.0
  y:
    specifier: ^1.0.0
    version: 1.0.0

packages:

  /common@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    dev: false

  /host@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    dev: false

  /host@2.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    dev: false

  /plug@1.0.0(host@1.0.0):
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    peerDependencies:
      host: '*'
    dependencies:
      common: 1.0.0
      host: 1.0.0
    dev: false

  /plug@1.0.0(host@2.0.0):
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    peerDependencies:
      host: '*'
    dependencies:
      common: 1.0.0
      host: 2.0.0
    dev: false

  /x@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    dependencies:
      host: 1.0.0
      plug: 1.0.0(host@1.0.0)
    dev: false

  /y@1.0.0:
    resolution: {integrity: sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==}
    dependencies:
      host: 2.0.0
      plug: 1.0.0(host@2.0.0)
    dev: false
`,
}

// TestParsePnpmLockPeerVariants checks that the entries pnpm writes for one
// package resolved against different peers fold into one package holding
// the union of their edges.
func TestParsePnpmLockPeerVariants(t *testing.T) {
	t.Parallel()
	for name, doc := range pnpmPeerVariantsLock {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lock, err := ParsePnpmLock([]byte(doc))
			require.NoError(t, err)

			plug := lock.Packages["plug@1.0.0"]
			require.NotNil(t, plug)
			require.Equal(t, map[string][]string{
				"common": {"1.0.0"},
				"host":   {"1.0.0", "2.0.0"},
			}, plug.DependencyVersions)

			// The single-version form keeps the variant that sorts first.
			require.Equal(t, map[string]string{"common": "1.0.0", "host": "1.0.0"}, plug.Dependencies)

			// A package with no variants lists one version per name.
			require.Equal(t, map[string][]string{
				"host": {"1.0.0"},
				"plug": {"1.0.0"},
			}, lock.Packages["x@1.0.0"].DependencyVersions)
			require.Nil(t, lock.Packages["common@1.0.0"].DependencyVersions)
		})
	}
}

// TestExtractPnpmPeerVariants checks the graph of the same lock: one node
// for the package, with an edge to each version its variants resolve.
func TestExtractPnpmPeerVariants(t *testing.T) {
	t.Parallel()
	for name, doc := range pnpmPeerVariantsLock {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(
				`{"name": "variants", "version": "1.0.0", "dependencies": {"x": "^1.0.0", "y": "^1.0.0"}}`,
			), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(doc), 0o600))

			nl, err := New().Extract(&api.DecomposerOptions{WorkDir: dir, Networking: api.NetworkDisabled})
			require.NoError(t, err)

			hosts := map[string]*sbom.Node{}
			for _, n := range nl.GetNodes() {
				if n.GetName() == "host" {
					hosts[n.GetVersion()] = n
				}
			}
			require.Len(t, hosts, 2)

			// pnpmNodeNamed requires a single node of the name.
			plug := pnpmNodeNamed(t, nl, "plug")
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, pnpmNodeNamed(t, nl, "x"), plug))
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, pnpmNodeNamed(t, nl, "y"), plug))
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, plug, hosts["1.0.0"]))
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, plug, hosts["2.0.0"]))
			require.True(t, pnpmHasEdge(nl, sbom.Edge_dependsOn, plug, pnpmNodeNamed(t, nl, "common")))
		})
	}
}

// TestExtractPnpmAliases reads a lock where a package is installed under
// another name, in the spelling of each schema generation: the reference
// is the key of the package installed, and the node is that package's,
// shared with whoever requires it under its own name.
func TestExtractPnpmAliases(t *testing.T) {
	t.Parallel()

	const integrity = "sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA=="
	for name, doc := range map[string]string{
		"schema 9": `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      pad:
        specifier: npm:lodash.padstart@^4.6.1
        version: lodash.padstart@4.6.1
      user:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  '@types/node@20.1.0':
    resolution: {integrity: ` + integrity + `}

  lodash.padstart@4.6.1:
    resolution: {integrity: ` + integrity + `}

  user@1.0.0:
    resolution: {integrity: ` + integrity + `}

snapshots:

  '@types/node@20.1.0': {}

  lodash.padstart@4.6.1: {}

  user@1.0.0:
    dependencies:
      '@me/scoped': '@types/node@20.1.0'
      lodash.padstart: 4.6.1
`,
		"schema 6": `lockfileVersion: '6.0'

dependencies:
  pad:
    specifier: npm:lodash.padstart@^4.6.1
    version: /lodash.padstart@4.6.1
  user:
    specifier: ^1.0.0
    version: 1.0.0

packages:

  /@types/node@20.1.0:
    resolution: {integrity: ` + integrity + `}
    dev: false

  /lodash.padstart@4.6.1:
    resolution: {integrity: ` + integrity + `}
    dev: false

  /user@1.0.0:
    resolution: {integrity: ` + integrity + `}
    dependencies:
      '@me/scoped': /@types/node@20.1.0
      lodash.padstart: 4.6.1
    dev: false
`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(
				`{"name": "alias-app", "version": "1.0.0"}`), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(doc), 0o600))

			nl, err := New().Extract(&api.DecomposerOptions{WorkDir: dir, Networking: api.NetworkDisabled})
			require.NoError(t, err)
			require.Equal(t, []string{
				"alias-app -> lodash.padstart@4.6.1 (dependsOn)",
				"alias-app -> user@1.0.0 (dependsOn)",
				"user -> @types/node@20.1.0 (dependsOn)",
				"user -> lodash.padstart@4.6.1 (dependsOn)",
			}, npmEdges(nl))
		})
	}
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

// writeConfig writes a configuration file into a temp dir and returns its
// path.
func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// TestRegistryConfigPublic checks which packages a configuration leaves to
// the public registry, read from each of the files that can say.
func TestRegistryConfigPublic(t *testing.T) {
	t.Parallel()

	const private = "https://npm.acme.example/"
	for name, tc := range map[string]struct {
		read   func(t *testing.T, rc *registryConfig)
		public map[string]bool
	}{
		"nothing configured": {
			func(*testing.T, *registryConfig) {},
			map[string]bool{"debug": true, "@acme/secret": true},
		},
		"a file that is not there": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(filepath.Join(t.TempDir(), ".npmrc"))
				rc.readYarnrc(filepath.Join(t.TempDir(), ".yarnrc.yml"))
				rc.readPnpmWorkspace(filepath.Join(t.TempDir(), "pnpm-workspace.yaml"))
			},
			map[string]bool{"debug": true, "@acme/secret": true},
		},
		"npmrc: a private default": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", "; the company mirror\nregistry = "+private+"\n"))
			},
			map[string]bool{"debug": false, "@acme/secret": false},
		},
		"npmrc: the public registry spelled out": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", `registry="https://registry.npmjs.org/"`+"\n"))
			},
			map[string]bool{"debug": true, "@acme/secret": true},
		},
		"npmrc: a private scope": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", "# only ours\n@acme:registry="+private+"\nsave-exact=true\n"))
			},
			map[string]bool{"debug": true, "@acme/secret": false, "@ACME/Other": false, "@types/node": true, "acme": true},
		},
		"npmrc: a private default and a public scope": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", "registry="+private+"\n@types:registry=https://registry.npmjs.org/\n"))
			},
			map[string]bool{"debug": false, "@types/node": true},
		},
		"npmrc: a registry over plain http is not the public one": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", "registry=http://registry.npmjs.org/\n"))
			},
			map[string]bool{"debug": false},
		},
		"npmrc: a value left to the environment could be anything": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", "@acme:registry=${ACME_REGISTRY}\n"))
			},
			map[string]bool{"debug": false, "@acme/secret": false},
		},
		"a later file overrides an earlier one": {
			func(t *testing.T, rc *registryConfig) {
				rc.readNpmrc(writeConfig(t, ".npmrc", "registry="+private+"\n"))
				rc.readNpmrc(writeConfig(t, ".npmrc", "registry=https://registry.npmjs.org/\n"))
			},
			map[string]bool{"debug": true},
		},
		"pnpm-workspace.yaml": {
			func(t *testing.T, rc *registryConfig) {
				rc.readPnpmWorkspace(writeConfig(t, "pnpm-workspace.yaml",
					"packages:\n  - packages/*\nregistries:\n  default: https://registry.npmjs.org/\n  '@acme': "+private+"\n"))
			},
			map[string]bool{"debug": true, "@acme/secret": false},
		},
		"yarnrc: a private default": {
			func(t *testing.T, rc *registryConfig) {
				rc.readYarnrc(writeConfig(t, ".yarnrc.yml", "nodeLinker: node-modules\nnpmRegistryServer: \""+private+"\"\n"))
			},
			map[string]bool{"debug": false},
		},
		"yarnrc: a private scope, written without its @": {
			func(t *testing.T, rc *registryConfig) {
				rc.readYarnrc(writeConfig(t, ".yarnrc.yml", "npmScopes:\n  acme:\n    npmRegistryServer: "+private+"\n"))
			},
			map[string]bool{"debug": true, "@acme/secret": false},
		},
		"yarnrc: not YAML": {
			func(t *testing.T, rc *registryConfig) {
				rc.readYarnrc(writeConfig(t, ".yarnrc.yml", "npmRegistryServer: [unclosed\n"))
			},
			map[string]bool{"debug": false, "@acme/secret": false},
		},
		"a file that cannot be read": {
			func(t *testing.T, rc *registryConfig) {
				// A directory where the file should be.
				rc.readNpmrc(t.TempDir())
			},
			map[string]bool{"debug": false},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rc := &registryConfig{}
			tc.read(t, rc)
			for pkg, expected := range tc.public {
				require.Equal(t, expected, rc.public(pkg), pkg)
			}
		})
	}
}

// TestParseYarnBerryFromNpm checks which berry entries are the registry's
// as they stand: those resolved through the npm protocol.
func TestParseYarnBerryFromNpm(t *testing.T) {
	t.Parallel()

	lock, err := ParseYarnBerryLock([]byte(`__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  languageName: unknown
  linkType: soft

"debug@npm:^4.3.4":
  version: 4.4.3
  resolution: "debug@npm:4.4.3"
  languageName: node
  linkType: hard

"fromgit@https://github.com/acme/fromgit.git":
  version: 1.0.0
  resolution: "fromgit@https://github.com/acme/fromgit.git#commit=0123456789abcdef0123456789abcdef01234567"
  languageName: node
  linkType: hard

"typescript@patch:typescript@npm%3A^5.4.0#optional!builtin<compat/typescript>":
  version: 5.4.5
  resolution: "typescript@patch:typescript@npm%3A5.4.5#optional!builtin<compat/typescript>::version=5.4.5&hash=5adc0c"
  languageName: node
  linkType: hard
`))
	require.NoError(t, err)

	require.True(t, lock.Entries["debug@npm:^4.3.4"].FromNpm)
	require.False(t, lock.Workspaces["."].FromNpm)
	require.False(t, lock.Entries["fromgit@https://github.com/acme/fromgit.git"].FromNpm)
	require.False(t, lock.Entries["typescript@patch:typescript@npm%3A^5.4.0#optional!builtin<compat/typescript>"].FromNpm)
}

// TestRegistryEnrichByConfig checks that with a lock that does not say
// where packages came from, only those the configuration leaves to the
// public registry are asked about, and never the project's own.
func TestRegistryEnrichByConfig(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	requested := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.EscapedPath())
		mu.Unlock()
		// The tarball of whatever is asked for, on the public registry,
		// except for one version said to be served from elsewhere.
		tarball := "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
		if r.URL.EscapedPath() == "/@types%2Fnode/20.1.0" {
			tarball = "https://mirror.example/node-20.1.0.tgz"
		}
		//nolint:errcheck // a fake server's writes have nowhere to fail
		fmt.Fprintf(w, `{"_npmUser": {"name": "publisher"}, "dist": {"tarball": %q, "shasum": "574c8138ce1d2b5861f0b44579dbadd60c6615b2"}}`, tarball)
	}))
	defer server.Close()

	nl := sbom.NewNodeList()
	root := &sbom.Node{Id: "root", Name: "app", Version: "1.0.0"}
	member := &sbom.Node{Id: "member", Name: "@acme/member", Version: "1.0.0"}
	nl.AddRootNode(root)
	nl.AddRootNode(member)
	add := func(id, name, version, download string) *sbom.Node {
		node := &sbom.Node{Id: id, Name: name, Version: version, UrlDownload: download}
		require.NoError(t, nl.RelateNodeAtID(node, root.GetId(), sbom.Edge_dependsOn))
		return node
	}
	debug := add("debug", "debug", "4.4.3", "")
	types := add("types", "@types/node", "20.1.0", "")
	secret := add("secret", "@acme/secret", "1.0.0", "")
	tarball := add("tarball", "fromtarball", "1.0.0", "https://npm.acme.example/fromtarball-1.0.0.tgz")
	publicTarball := add("ptarball", "pinned", "2.0.0", "https://registry.npmjs.org/pinned/-/pinned-2.0.0.tgz")
	linked := add("linked", "linked", "link:../linked", "")
	byFile := add("file", "byfile", "file:vendor/byfile", "")

	// The rule pnpm graphs are read by, over a configuration with one
	// private scope.
	config := &registryConfig{}
	config.setScope("@acme", "https://npm.acme.example/")
	public := func(node *sbom.Node) bool {
		if node.GetUrlDownload() != "" {
			return fromPublicRegistry(node)
		}
		return config.public(node.GetName())
	}

	client := NewRegistryClient(2)
	client.BaseURL = server.URL
	client.enrichNodes(nl, public)

	sort.Strings(requested)
	require.Equal(t, []string{"/@types%2Fnode/20.1.0", "/debug/4.4.3", "/pinned/2.0.0"}, requested)

	for _, node := range []*sbom.Node{debug, types, publicTarball} {
		require.Len(t, node.GetSuppliers(), 1, node.GetName())
		require.NotEmpty(t, node.GetHashes(), node.GetName())
	}

	// A node the lock gave no location takes the registry's tarball,
	// when that is on the public registry; one that has a location keeps
	// it.
	require.Equal(t, "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", debug.GetUrlDownload())
	require.Empty(t, types.GetUrlDownload())
	require.Equal(t, "https://registry.npmjs.org/pinned/-/pinned-2.0.0.tgz", publicTarball.GetUrlDownload())
	for _, node := range []*sbom.Node{root, member, secret, tarball, linked, byFile} {
		require.Empty(t, node.GetSuppliers(), node.GetName())
		require.Empty(t, node.GetHashes(), node.GetName())
	}

	// With the configuration undecided, nothing it would have to settle
	// is asked about.
	requested = nil
	undecided := &registryConfig{undecided: true}
	client.enrichNodes(nl, func(node *sbom.Node) bool { return undecided.public(node.GetName()) })
	require.Empty(t, requested)
}

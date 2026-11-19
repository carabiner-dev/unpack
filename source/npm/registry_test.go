// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

// TestRegistrySupplier checks who a published version is supplied by, over
// the shapes the registry answers with. The cases are what it states for
// the packages named.
func TestRegistrySupplier(t *testing.T) {
	t.Parallel()

	type person struct{ name, email, url string }
	for name, tc := range map[string]struct {
		doc      string
		expected *person
	}{
		// debug: an author object, and another account publishing.
		"the declared author over the publisher": {
			`{"author": {"name": "Josh Junon", "url": "https://github.com/qix-"}, "_npmUser": {"name": "qix", "email": "npm@josh.junon.me"}}`,
			&person{"Josh Junon", "", "https://github.com/qix-"},
		},
		// react: no author, so the account that published it.
		"the publisher when no author is declared": {
			`{"_npmUser": {"name": "react-bot", "email": "react-core@meta.com"}}`,
			&person{"react-bot", "react-core@meta.com", ""},
		},
		"an author written as one string": {
			`{"author": "Barney Rubble <b@rubble.com> (http://barnyrubble.tumblr.com/)"}`,
			&person{"Barney Rubble", "b@rubble.com", "http://barnyrubble.tumblr.com/"},
		},
		"a string with a name alone": {
			`{"author": "Microsoft Corp."}`,
			&person{"Microsoft Corp.", "", ""},
		},
		"a string with a name and a url": {
			`{"author": "Jane Doe (https://jane.example)"}`,
			&person{"Jane Doe", "", "https://jane.example"},
		},
		"an author with no name falls to the publisher": {
			`{"author": {"email": "nobody@example.com"}, "_npmUser": {"name": "publisher"}}`,
			&person{"publisher", "", ""},
		},
		"an author that is neither form": {
			`{"author": 42, "_npmUser": {"name": "publisher"}}`,
			&person{"publisher", "", ""},
		},
		"nobody named": {`{"license": "MIT"}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			version := &registryVersion{}
			require.NoError(t, json.Unmarshal([]byte(tc.doc), version))
			supplier := version.supplier()
			if tc.expected == nil {
				require.Nil(t, supplier)
				return
			}
			require.NotNil(t, supplier)
			require.Equal(t, *tc.expected, person{supplier.GetName(), supplier.GetEmail(), supplier.GetUrl()})
		})
	}
}

// TestRegistryLicenses checks the licenses a published version declares,
// over the forms manifests have written them in.
func TestRegistryLicenses(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		doc      string
		expected []string
	}{
		"an SPDX identifier":       {`{"license": "MIT"}`, []string{"MIT"}},
		"an SPDX expression":       {`{"license": "(MIT OR Apache-2.0)"}`, []string{"(MIT OR Apache-2.0)"}},
		"a name the catalog knows": {`{"license": "Apache License 2.0"}`, []string{"Apache-2.0"}},
		// Older manifests: an object, and a list of them.
		"an object":               {`{"license": {"type": "ISC", "url": "https://opensource.org/licenses/ISC"}}`, []string{"ISC"}},
		"a list":                  {`{"licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}, {"type": "MIT"}]}`, []string{"MIT", "Apache-2.0"}},
		"a list of strings":       {`{"licenses": ["MIT", "BSD-3-Clause"]}`, []string{"MIT", "BSD-3-Clause"}},
		"the field over the list": {`{"license": "MIT", "licenses": [{"type": "GPL-2.0-only"}]}`, []string{"MIT"}},
		// What npm gives a meaning of its own, and states no license.
		"no license granted":  {`{"license": "UNLICENSED"}`, []string{}},
		"a pointer to a file": {`{"license": "SEE LICENSE IN LICENSE.md"}`, []string{}},
		"an empty value":      {`{"license": ""}`, []string{}},
		"neither form":        {`{"license": 42}`, []string{}},
		"nothing declared":    {`{"_npmUser": {"name": "publisher"}}`, []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			version := &registryVersion{}
			require.NoError(t, json.Unmarshal([]byte(tc.doc), version))
			require.Equal(t, tc.expected, version.licenses())
		})
	}
}

func TestRegistryVersionURL(t *testing.T) {
	t.Parallel()
	client := NewRegistryClient(0)
	require.Equal(t, "https://registry.npmjs.org/debug/4.4.3", client.versionURL("debug", "4.4.3"))
	// The slash of a scoped name is escaped.
	require.Equal(t, "https://registry.npmjs.org/@types%2Fnode/20.1.0", client.versionURL("@types/node", "20.1.0"))
}

// TestRegistryEnrich checks that only packages their lock says came from
// the public registry are asked about, by name and version, and that what
// it answers reaches every node of the package.
func TestRegistryEnrich(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	requested := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.EscapedPath())
		mu.Unlock()
		switch r.URL.EscapedPath() {
		case "/debug/4.4.3":
			fmt.Fprint(w, `{"license": "MIT", "author": {"name": "Josh Junon"}, "_npmUser": {"name": "qix"}}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		case "/@types%2Fnode/20.1.0":
			fmt.Fprint(w, `{"license": "MIT", "_npmUser": {"name": "types", "email": "ts-npm-types@microsoft.com"}}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	nl := sbom.NewNodeList()
	root := &sbom.Node{Id: "root", Name: "app", Version: "1.0.0"}
	nl.AddRootNode(root)
	add := func(id, name, version, download string) *sbom.Node {
		node := &sbom.Node{Id: id, Name: name, Version: version, UrlDownload: download}
		require.NoError(t, nl.RelateNodeAtID(node, root.GetId(), sbom.Edge_dependsOn))
		return node
	}
	debug := add("debug", "debug", "4.4.3", "https://registry.npmjs.org/debug/-/debug-4.4.3.tgz")
	// The same package installed at a second path, fetched from the
	// mirror Yarn writes: one request, both nodes.
	debugAgain := add("debug2", "debug", "4.4.3", "https://registry.yarnpkg.com/debug/-/debug-4.4.3.tgz#abc")
	types := add("types", "@types/node", "20.1.0", "https://registry.npmjs.org/@types/node/-/node-20.1.0.tgz")
	// The lock recorded a license for this one, which stands whatever
	// the registry says now.
	types.Licenses = []string{"Apache-2.0"}
	unknown := add("unknown", "unknown", "1.0.0", "https://registry.npmjs.org/unknown/-/unknown-1.0.0.tgz")

	// None of these is the public registry's to describe.
	private := add("private", "@acme/secret", "1.0.0", "https://npm.acme.example/@acme/secret/-/secret-1.0.0.tgz")
	insecure := add("insecure", "plain", "1.0.0", "http://registry.npmjs.org/plain/-/plain-1.0.0.tgz")
	fromGit := add("git", "fromgit", "1.0.0", "git+ssh://git@github.com/acme/fromgit.git#0123")
	noLocation := add("none", "nowhere", "1.0.0", "")

	client := NewRegistryClient(2)
	client.BaseURL = server.URL
	client.enrichNodes(nl, fromPublicRegistry)

	sort.Strings(requested)
	require.Equal(t, []string{"/@types%2Fnode/20.1.0", "/debug/4.4.3", "/unknown/1.0.0"}, requested)

	for _, node := range []*sbom.Node{debug, debugAgain} {
		require.Len(t, node.GetSuppliers(), 1)
		require.Equal(t, "Josh Junon", node.GetSuppliers()[0].GetName())
	}
	require.NotSame(t, debug.GetSuppliers()[0], debugAgain.GetSuppliers()[0])

	require.Len(t, types.GetSuppliers(), 1)
	require.Equal(t, "types", types.GetSuppliers()[0].GetName())
	require.Equal(t, "ts-npm-types@microsoft.com", types.GetSuppliers()[0].GetEmail())

	// The license comes with the same answer, for a node that had none.
	require.Equal(t, []string{"MIT"}, debug.GetLicenses())
	require.Equal(t, []string{"MIT"}, debugAgain.GetLicenses())
	require.Equal(t, []string{"Apache-2.0"}, types.GetLicenses())

	for _, node := range []*sbom.Node{root, unknown, private, insecure, fromGit, noLocation} {
		require.Empty(t, node.GetSuppliers(), node.GetName())
		require.Empty(t, node.GetLicenses(), node.GetName())
	}
}

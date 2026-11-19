// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

const testZipHash = "d8dac1115c17fa667a93d50f34ddf37648eeb6b92446f429c6120777aa839678"

func TestEtagHash(t *testing.T) {
	t.Parallel()
	for etag, expected := range map[string]string{
		`"` + testZipHash + `"`: testZipHash,
		testZipHash:             testZipHash,
		// A weak tag does not speak for the bytes.
		`W/"` + testZipHash + `"`: "",
		// Whatever else a server may choose.
		`"abc123"`: "",
		`"D8DAC1115C17FA667A93D50F34DDF37648EEB6B92446F429C6120777AA839678"`: "",
		`"` + testZipHash + `-gzip"`:                                         "",
		"":                                                                   "",
	} {
		require.Equal(t, expected, etagHash(etag), etag)
	}
}

func TestProxyStatesZipHashes(t *testing.T) {
	t.Parallel()
	for proxy, expected := range map[string]bool{
		"https://proxy.golang.org":       true,
		"https://proxy.golang.org/":      true,
		"http://proxy.golang.org":        false,
		"https://goproxy.example.com":    false,
		"https://proxy.golang.org.evil":  false,
		"https://athens.internal/golang": false,
		"":                               false,
		"://":                            false,
	} {
		require.Equal(t, expected, proxyStatesZipHashes(proxy), proxy)
	}
}

func TestZipURL(t *testing.T) {
	t.Parallel()
	location, ok := zipURL("https://proxy.golang.org/", "github.com/BurntSushi/toml", "v1.4.0-RC1")
	require.True(t, ok)
	require.Equal(t, "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0-!r!c1.zip", location)

	_, ok = zipURL("https://proxy.golang.org", "not a module path", "v1.0.0")
	require.False(t, ok)
}

func TestGoSumProperties(t *testing.T) {
	t.Parallel()
	sums := map[string][]string{
		"a@v1.0.0": {"h1:abc="},
		"b@v1.0.0": {"h2:future=", "h1:"},
	}
	require.Equal(t, []*sbom.Property{{Name: PropertyH1, Data: "h1:abc="}}, goSumProperties("a@v1.0.0", sums))
	require.Empty(t, goSumProperties("b@v1.0.0", sums))
	require.Empty(t, goSumProperties("missing@v1.0.0", sums))
	require.Empty(t, goSumProperties("a@v1.0.0", nil))
}

// TestFetchZipHashes checks the proxy is asked with a HEAD for each
// module's zip, that a hash it states reaches the node with the zip's
// location, and that a module it states nothing usable for keeps no hash
// and the location it had.
func TestFetchZipHashes(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	asked := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path] = r.Method
		mu.Unlock()
		switch r.URL.Path {
		case "/example.com/hashed/@v/v1.0.0.zip":
			w.Header().Set("ETag", `"`+testZipHash+`"`)
		case "/example.com/opaque/@v/v1.0.0.zip":
			w.Header().Set("ETag", `"some-other-tag"`)
		case "/example.com/untagged/@v/v1.0.0.zip":
		case "/example.com/large/@v/v1.0.0.zip":
			// A large zip is a redirect to where it is stored, with the
			// hash stated on the redirect.
			w.Header().Set("ETag", `"`+testZipHash+`"`)
			http.Redirect(w, r, "/stored/large.zip", http.StatusFound)
		case "/stored/large.zip":
			w.Header().Set("ETag", `"the-stores-own-tag"`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	node := func(name string) *sbom.Node {
		return &sbom.Node{Name: name, Version: "v1.0.0", UrlDownload: "as-it-was", Hashes: map[int32]string{}}
	}
	hashed, opaque, untagged, missing := node("example.com/hashed"), node("example.com/opaque"),
		node("example.com/untagged"), node("example.com/missing")
	large := node("example.com/large")

	fetchZipHashes(t.Context(), server.Client(), server.URL, []*sbom.Node{hashed, opaque, untagged, missing, large}, 2)

	require.Equal(t, map[int32]string{int32(sbom.HashAlgorithm_SHA256): testZipHash}, hashed.GetHashes())
	require.Equal(t, server.URL+"/example.com/hashed/@v/v1.0.0.zip", hashed.GetUrlDownload())

	// The redirect is not followed: the hash is the one stated on it,
	// and the store is never asked.
	require.Equal(t, map[int32]string{int32(sbom.HashAlgorithm_SHA256): testZipHash}, large.GetHashes())
	require.Equal(t, server.URL+"/example.com/large/@v/v1.0.0.zip", large.GetUrlDownload())
	require.NotContains(t, asked, "/stored/large.zip")
	for _, n := range []*sbom.Node{opaque, untagged, missing} {
		require.Empty(t, n.GetHashes(), n.GetName())
		require.Equal(t, "as-it-was", n.GetUrlDownload(), n.GetName())
	}

	require.Len(t, asked, 5)
	for path, method := range asked {
		require.Equal(t, http.MethodHead, method, path)
	}
}

// TestModuleNodes checks which nodes of a graph the proxy is asked about.
func TestModuleNodes(t *testing.T) {
	t.Parallel()
	nl := sbom.NewNodeList()
	for _, n := range []*sbom.Node{
		{Id: "root", Name: "example.com/app", Version: "v1.0.0"},
		{Id: "std", Name: stdlibName, Version: "1.24.0"},
		{Id: "local", Name: "../sibling", Version: "v0.0.0"},
		{Id: "unversioned", Name: "example.com/unversioned"},
		{Id: "dep", Name: "example.com/dep", Version: "v1.2.3"},
	} {
		nl.AddNode(n)
	}
	nodes := moduleNodes(nl, "example.com/app")
	require.Len(t, nodes, 1)
	require.Equal(t, "example.com/dep", nodes[0].GetName())
}

// TestHashModuleZipsOtherProxy checks a proxy other than the one known to
// state zip hashes is not asked at all.
func TestHashModuleZipsOtherProxy(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("ETag", `"`+testZipHash+`"`)
	}))
	defer server.Close()

	nl := sbom.NewNodeList()
	dep := &sbom.Node{Id: "dep", Name: "example.com/dep", Version: "v1.2.3"}
	nl.AddNode(dep)

	d := Decomposer{}
	d.hashModuleZips(t.Context(), nl, "example.com/app", &Options{ProxyURL: server.URL, HTTPClient: server.Client()})
	require.Zero(t, requests)
	require.Empty(t, dep.GetHashes())
}

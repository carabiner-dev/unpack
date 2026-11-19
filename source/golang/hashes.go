// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/mod/module"
)

// This file is about what a Go module hashes to.
//
// The checksum go.sum and a Go binary record for a module, "h1:", is not
// the hash of a file. It is the SHA-256 of a listing of the module's files
// with the SHA-256 of each, so that a zip and its extracted tree hash the
// same. It is a SHA-256 in name only: hashing the zip a node's download URL
// names gives another value, and a reader comparing the two would see
// tampering where there is none. So it is recorded as what it is, a
// property of the node, and not among its hashes.
//
// The hash of the zip itself is stated by the module proxy: proxy.golang.org
// answers a request for a zip with its SHA-256 as the entity tag, which a
// HEAD request reads without fetching the file. The protocol does not
// promise it, so the value is taken only from that proxy and only when it
// has the shape of a SHA-256; the conformance test holds it to the zip.
//
// The proxy serves a large zip by redirecting to where it is stored, and
// states the hash on the redirect itself. The store's own entity tag is
// another thing, so redirects are not followed: the answer read is the
// proxy's.

// PropertyH1 names the property holding a module's go.sum checksum, as go
// writes it: "h1:" and the base64 of the module tree's hash.
const PropertyH1 = "go:h1"

// stdlibName is the name of the node standing for the standard library.
const stdlibName = "stdlib"

// h1Prefix opens the checksums of the one hash scheme go has defined.
const h1Prefix = "h1:"

// goSumProperties returns the module's go.sum checksum as node properties.
func goSumProperties(modKey string, sumHashes map[string][]string) []*sbom.Property {
	for _, sum := range sumHashes[modKey] {
		if strings.HasPrefix(sum, h1Prefix) && len(sum) > len(h1Prefix) {
			return []*sbom.Property{{Name: PropertyH1, Data: sum}}
		}
	}
	return nil
}

// zipHashProxy is the host whose entity tags are the SHA-256 of the zips
// it serves.
const zipHashProxy = "proxy.golang.org"

// proxyStatesZipHashes says whether the proxy at the URL is one whose
// entity tags are known to be the hash of its zips. Another proxy's may be
// anything.
func proxyStatesZipHashes(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() == zipHashProxy
}

// sha256Hex matches a SHA-256 written in hexadecimal.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// etagHash reads a SHA-256 off an entity tag, and nothing off a tag that
// is not one: a weak tag, which does not speak for the bytes, or any other
// value a server may choose.
func etagHash(etag string) string {
	value := strings.Trim(strings.TrimSpace(etag), `"`)
	if !sha256Hex.MatchString(value) {
		return ""
	}
	return value
}

// zipURL returns where the proxy serves a module's zip, with the path and
// version escaped as the proxy protocol has them (capitals as "!c").
func zipURL(proxyURL, modPath, version string) (string, bool) {
	escapedPath, err := module.EscapePath(modPath)
	if err != nil {
		return "", false
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(proxyURL, "/") + "/" + escapedPath + "/@v/" + escapedVersion + ".zip", true
}

// hashModuleZips sets on every module node the SHA-256 of its zip as the
// proxy states it, and the zip's location with it, so that the hash is of
// the file the node says to download. A module the proxy states nothing
// usable for is left without a hash.
func (d *Decomposer) hashModuleZips(nl *sbom.NodeList, rootModule string, opts *Options) {
	proxyURL := opts.ProxyURL
	if proxyURL == "" {
		proxyURL = defaultProxyURL
	}
	if !proxyStatesZipHashes(proxyURL) {
		return
	}
	fetchZipHashes(opts.HTTPClient, proxyURL, moduleNodes(nl, rootModule), opts.Concurrency)
}

// moduleNodes returns the nodes of the graph that are modules a proxy
// serves: not the main module, the standard library or a local directory.
func moduleNodes(nl *sbom.NodeList, rootModule string) []*sbom.Node {
	nodes := []*sbom.Node{}
	for _, node := range nl.GetNodes() {
		name, version := node.GetName(), node.GetVersion()
		if name == "" || version == "" || name == rootModule || name == stdlibName || isLocalReplace(name) {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// fetchZipHashes asks the proxy for the entity tag of each node's zip and
// sets the hash it states on the node. A nil client is the default one.
func fetchZipHashes(client *http.Client, proxyURL string, nodes []*sbom.Node, concurrency int) {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	// The caller's client, made to stop at the proxy's own answer.
	own := http.Client{Timeout: defaultHTTPTimeout}
	if client != nil {
		own = *client
	}
	own.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &own

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, node := range nodes {
		location, ok := zipURL(proxyURL, node.GetName(), node.GetVersion())
		if !ok {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		// Each goroutine writes to its own node and no other.
		go func(node *sbom.Node, location string) {
			defer wg.Done()
			defer func() { <-sem }()

			hash := headZipHash(client, location)
			if hash == "" {
				return
			}
			node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): hash}
			node.UrlDownload = location
		}(node, location)
	}
	wg.Wait()
}

// headZipHash returns the SHA-256 the proxy states for the zip at the
// location, or nothing. The client must not follow redirects: the proxy
// states the hash where it answers, with the file or with a redirect to
// it.
func headZipHash(client *http.Client, location string) string {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, location, http.NoBody)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck // nothing was read from it
	if resp.StatusCode != http.StatusOK && (resp.StatusCode < 300 || resp.StatusCode > 399) {
		return ""
	}
	return etagHash(resp.Header.Get("ETag"))
}

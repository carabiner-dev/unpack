// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

func extractRuby(t *testing.T, testdata, platform string) *sbom.NodeList {
	t.Helper()
	opts := &api.DecomposerOptions{WorkDir: "testdata/" + testdata, Platform: platform}
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

func hasEdge(nl *sbom.NodeList, from, to *sbom.Node) bool {
	for _, e := range nl.GetEdges() {
		if e.GetType() == sbom.Edge_dependsOn && e.GetFrom() == from.GetId() {
			for _, id := range e.GetTo() {
				if id == to.GetId() {
					return true
				}
			}
		}
	}
	return false
}

func TestExtractRuby(t *testing.T) {
	t.Parallel()

	nl := extractRuby(t, "simple", "linux/amd64")

	// The lock names no project: the directory lends its name.
	root := nodeNamed(t, nl, "simple")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())

	// Every direct dependency is a plain edge — the development-group gem
	// among them, since the lock does not know groups.
	sinatra := nodeNamed(t, nl, "sinatra")
	minitest := nodeNamed(t, nl, "minitest")
	require.True(t, hasEdge(nl, root, sinatra))
	require.True(t, hasEdge(nl, root, minitest))

	// The resolved tree: sinatra's edges, and rack shared below.
	rack := nodeNamed(t, nl, "rack")
	require.True(t, hasEdge(nl, root, nodeNamed(t, nl, "ffi")))
	require.True(t, hasEdge(nl, sinatra, rack))
	require.True(t, hasEdge(nl, nodeNamed(t, nl, "rack-protection"), rack))
	require.True(t, hasEdge(nl, minitest, nodeNamed(t, nl, "prism")))

	// The registry download URL is conventional.
	require.Equal(t, "https://rubygems.org/downloads/sinatra-4.2.1.gem", sinatra.GetUrlDownload())
}

// TestExtractRubyPlatforms covers the variant selection: one lock, three
// targets, three different ffi artifacts — and the checksum follows the
// artifact.
func TestExtractRubyPlatforms(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		platform string
		purl     string
	}{
		"linux prefers the glibc build": {
			"linux/amd64", "pkg:gem/ffi@1.17.4?platform=x86_64-linux-gnu",
		},
		"a mac gets the darwin build": {
			"darwin/arm64", "pkg:gem/ffi@1.17.4?platform=arm64-darwin",
		},
		// The lock holds no mingw build, so windows falls back to the
		// pure-Ruby variant.
		"windows falls back to pure ruby": {
			"windows/amd64", "pkg:gem/ffi@1.17.4",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nl := extractRuby(t, "simple", tc.platform)
			ffi := nodeNamed(t, nl, "ffi")
			require.Equal(t, tc.purl,
				ffi.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
			require.NotEmpty(t, ffi.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
		})
	}

	// The three artifacts hash differently, and each node carries its
	// own artifact's checksum.
	linux := nodeNamed(t, extractRuby(t, "simple", "linux/amd64"), "ffi")
	mac := nodeNamed(t, extractRuby(t, "simple", "darwin/arm64"), "ffi")
	generic := nodeNamed(t, extractRuby(t, "simple", "windows/amd64"), "ffi")
	h := func(n *sbom.Node) string { return n.GetHashes()[int32(sbom.HashAlgorithm_SHA256)] }
	require.NotEqual(t, h(linux), h(mac))
	require.NotEqual(t, h(linux), h(generic))

	// A pure-Ruby gem is the same everywhere.
	require.Equal(t, "pkg:gem/sinatra@4.2.1",
		nodeNamed(t, extractRuby(t, "simple", "darwin/arm64"), "sinatra").
			GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
}

// TestExtractRubyGit covers a gem locked from a repository: the node
// carries the remote with the exact resolved commit, and no checksum,
// since there is no registry artifact to hash.
func TestExtractRubyGit(t *testing.T) {
	t.Parallel()

	nl := extractRuby(t, "gitgem", "linux/amd64")

	rake := nodeNamed(t, nl, "rake")
	require.Equal(t, "13.2.1", rake.GetVersion())
	require.Equal(t,
		"https://github.com/ruby/rake#1f0aa1682c53b756393c1eea2c3e7a921cbde9f4",
		rake.GetUrlDownload())
	require.Len(t, rake.GetExternalReferences(), 1)
	require.Equal(t, sbom.ExternalReference_VCS, rake.GetExternalReferences()[0].GetType())
	require.Empty(t, rake.GetHashes())
}

func TestGemPlatforms(t *testing.T) {
	t.Parallel()

	for platform, expected := range map[string][]string{
		"linux/amd64":   {"x86_64-linux-gnu", "x86_64-linux"},
		"linux/arm64":   {"aarch64-linux-gnu", "aarch64-linux"},
		"darwin/arm64":  {"arm64-darwin", "universal-darwin"},
		"windows/amd64": {"x64-mingw-ucrt", "x64-mingw32"},
	} {
		got, err := gemPlatforms(platform)
		require.NoError(t, err)
		require.Equal(t, expected, got, "platform %s", platform)
	}

	_, err := gemPlatforms("plan9/amd64")
	require.Error(t, err)
	_, err = gemPlatforms("linux/mips")
	require.Error(t, err)
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()

	index := code.PathIndex{}
	index.Add("app", "Gemfile.lock")
	index.Add("other", "go.mod")
	locations, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"app"}, locations)
}

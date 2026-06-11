// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The live tests pull real images pinned by digest, so every assertion is
// stable: registry content is immutable under its digest.
const (
	// alpine:3.21 at the time of pinning. The index lists 8 platforms, each
	// followed by a buildx attestation manifest that must be skipped.
	liveAlpineIndex = "alpine@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
	// The linux/amd64 member of that index.
	liveAlpineAmd64 = "alpine@sha256:f27cad9117495d32d067133afff942cb2dc745dfe9163e949f6bfe8a6a245339"
	// gcr.io/distroless/static-debian12 at the time of pinning: 5 platforms,
	// dpkg status.d databases, os-release behind a symlink.
	liveDistrolessIndex = "gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160"
)

// liveExtract runs the unpacker against a real registry, skipping the test
// when the network is unavailable unless UNPACK_FORCE_TESTS demands a
// failure (Linux only, matching the other conformance tests).
func liveExtract(t *testing.T, u *Unpacker, ref string) *sbom.NodeList {
	t.Helper()
	forceTests := os.Getenv("UNPACK_FORCE_TESTS") != "" && runtime.GOOS == "linux"

	lists, err := u.Extract(t.Context(), &Reference{Ref: ref})
	if err != nil {
		if forceTests {
			t.Fatalf("extracting %s: %v", ref, err)
		}
		t.Skipf("extracting %s failed (may need network): %v", ref, err)
	}
	require.Len(t, lists, 1)
	return lists[0]
}

func TestLiveExtractSingleArch(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	totals := map[string]int64{}
	progress := map[string]int64{}
	done := map[string]bool{}

	u := NewUnpacker()
	u.Options.Hooks = &PullHooks{
		LayerStart: func(digest string, total int64) {
			mu.Lock()
			defer mu.Unlock()
			totals[digest] = total
		},
		LayerProgress: func(digest string, complete, _ int64) {
			mu.Lock()
			defer mu.Unlock()
			progress[digest] = complete
		},
		LayerDone: func(digest string) {
			mu.Lock()
			defer mu.Unlock()
			done[digest] = true
		},
	}

	nl := liveExtract(t, u, liveAlpineAmd64)

	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	img := roots[0]
	assert.Equal(t, liveAlpineAmd64, img.GetName())
	assert.Equal(t, "linux/amd64", img.GetDescription())
	assert.Equal(t,
		strings.TrimPrefix(liveAlpineAmd64, "alpine@sha256:"),
		img.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
	)

	purl := img.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	assert.True(t, strings.HasPrefix(purl, "pkg:oci/alpine@sha256%3A"), purl)
	assert.Contains(t, purl, "arch=amd64")
	assert.NotContains(t, purl, "tag=", "digest references carry no tag")

	// This alpine digest ships exactly 15 packages.
	edge := nl.GetEdgeByType(img.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	assert.Len(t, edge.GetTo(), 15)

	musl := nl.GetNodesByName("musl")
	require.Len(t, musl, 1)
	assert.Equal(t, []string{"MIT"}, musl[0].GetLicenses())
	assert.Contains(t,
		musl[0].GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
		"pkg:apk/alpine/musl@",
	)

	// Every layer the hooks saw started, progressed to its full size, and
	// finished.
	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, totals)
	for digest, total := range totals {
		assert.True(t, done[digest], "layer %s never finished", digest)
		assert.Equal(t, total, progress[digest], "layer %s incomplete", digest)
	}
}

func TestLiveExtractMultiArch(t *testing.T) {
	t.Parallel()

	nl := liveExtract(t, NewUnpacker(), liveAlpineIndex)

	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	idx := roots[0]
	assert.Equal(t, "multi-arch image index", idx.GetDescription())
	assert.Equal(t,
		strings.TrimPrefix(liveAlpineIndex, "alpine@sha256:"),
		idx.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
	)

	// 8 platforms; the 8 interleaved attestation manifests are skipped.
	edge := nl.GetEdgeByType(idx.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 8)

	// Every platform image carries its own 15 packages, and the amd64
	// member matches the digest we pinned for the single-arch test.
	var sawAmd64 bool
	for _, id := range edge.GetTo() {
		archNode := nl.GetNodeByID(id)
		require.NotNil(t, archNode)
		pkgEdge := nl.GetEdgeByType(archNode.GetId(), sbom.Edge_contains)
		require.NotNil(t, pkgEdge, "platform %s has no packages", archNode.GetDescription())
		assert.Len(t, pkgEdge.GetTo(), 15, "platform %s", archNode.GetDescription())

		if archNode.GetDescription() == "linux/amd64" {
			sawAmd64 = true
			assert.Equal(t,
				strings.TrimPrefix(liveAlpineAmd64, "alpine@sha256:"),
				archNode.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
			)
		}
	}
	assert.True(t, sawAmd64, "linux/amd64 platform missing from the index")

	// 1 index + 8 platforms + 8×15 packages.
	assert.Len(t, nl.GetNodes(), 1+8+8*15)
}

func TestLiveExtractDistroless(t *testing.T) {
	t.Parallel()

	// Distroless exercises the deb decomposer through the whole stack:
	// status.d databases, an os-release symlink the tar filesystem must
	// resolve, and md5sums-only file lists.
	u := NewUnpacker()
	u.Options.IncludeFiles = true
	nl := liveExtract(t, u, liveDistrolessIndex)

	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	edge := nl.GetEdgeByType(roots[0].GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 5, "static-debian12 ships 5 platforms")

	for _, id := range edge.GetTo() {
		archNode := nl.GetNodeByID(id)
		pkgEdge := nl.GetEdgeByType(archNode.GetId(), sbom.Edge_contains)
		require.NotNil(t, pkgEdge, "platform %s has no packages", archNode.GetDescription())

		var sawBaseFiles bool
		for _, pid := range pkgEdge.GetTo() {
			pkg := nl.GetNodeByID(pid)
			if pkg.GetName() != "base-files" {
				continue
			}
			sawBaseFiles = true
			purl := pkg.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
			assert.True(t, strings.HasPrefix(purl, "pkg:deb/debian/base-files@"), purl)
			assert.Contains(t, purl, "distro=debian-12",
				"os-release must resolve through the image filesystem")

			// IncludeFiles: the md5sums-reconstructed file list hangs off
			// the package with MD5 digests.
			fileEdge := nl.GetEdgeByType(pkg.GetId(), sbom.Edge_contains)
			require.NotNil(t, fileEdge, "base-files should carry file nodes")
			f := nl.GetNodeByID(fileEdge.GetTo()[0])
			assert.NotEmpty(t, f.GetHashes()[int32(sbom.HashAlgorithm_MD5)])
		}
		assert.True(t, sawBaseFiles,
			"platform %s misses base-files", archNode.GetDescription())
	}
}

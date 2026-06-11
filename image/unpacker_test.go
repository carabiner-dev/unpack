// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/unpack/system"
)

// apkDB is a minimal two-package apk installed database, enough for the
// system decomposers to find and extract.
const apkDB = `C:Q1D35YJ+ThpzYxvtont4QxqLokDgU=
P:musl
V:1.2.6-r2
A:x86_64
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Natanael Copa <ncopa@alpinelinux.org>
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q1HDbpApgJLhKPJN6IjaA7wJ3Oa4o=

P:busybox-binsh
V:1.37.0-r30
A:x86_64
T:busybox ash /bin/sh
L:GPL-2.0-only
o:busybox
`

const alpineOSRelease = "ID=alpine\nVERSION_ID=3.24.0\n"

// pushTestImage builds a single-arch image carrying an apk database and
// pushes it to the test registry, returning its reference and digest.
func pushTestImage(t *testing.T, registryHost string) (string, v1.Hash) {
	t.Helper()

	layer := makeLayer(t,
		dir("lib"), dir("lib/apk"), dir("lib/apk/db"),
		file("lib/apk/db/installed", apkDB),
		dir("etc"),
		file("etc/os-release", alpineOSRelease),
	)
	img := makeImage(t, layer)
	img, err := mutate.ConfigFile(img, &v1.ConfigFile{Architecture: "amd64", OS: "linux"})
	require.NoError(t, err)

	refStr := registryHost + "/test/minialpine:v1"
	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img))

	digest, err := img.Digest()
	require.NoError(t, err)
	return refStr, digest
}

// startRegistry runs an in-memory OCI registry and returns its host:port.
func startRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

func TestExtractSingleArch(t *testing.T) {
	t.Parallel()

	host := startRegistry(t)
	refStr, digest := pushTestImage(t, host)

	u := NewUnpacker()
	lists, err := u.Extract(t.Context(), &Reference{Ref: refStr})
	require.NoError(t, err)
	require.Len(t, lists, 1)
	nl := lists[0]

	// One root: the image node.
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	img := roots[0]

	assert.Equal(t, refStr, img.GetName())
	assert.Equal(t, "v1", img.GetVersion())
	assert.Equal(t, []sbom.Purpose{sbom.Purpose_CONTAINER}, img.GetPrimaryPurpose())
	assert.Equal(t, "linux/amd64", img.GetDescription())

	// The manifest digest lands in the hashes.
	assert.Equal(t, digest.Hex, img.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	// The purl carries digest, arch, repository and tag.
	purl := img.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	assert.True(t, strings.HasPrefix(purl, "pkg:oci/minialpine@sha256%3A"), purl)
	assert.Contains(t, purl, "arch=amd64")
	assert.Contains(t, purl, "tag=v1")
	assert.Contains(t, purl, url.QueryEscape(host+"/test/minialpine"))

	// The apk packages hang off the image node via a contains edge.
	pkgsByName := map[string]*sbom.Node{}
	for _, n := range nl.GetNodes() {
		if n.GetId() != img.GetId() {
			pkgsByName[n.GetName()] = n
		}
	}
	require.Len(t, pkgsByName, 2)
	require.Contains(t, pkgsByName, "musl")
	require.Contains(t, pkgsByName, "busybox-binsh")
	assert.Contains(t,
		pkgsByName["musl"].GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
		"pkg:apk/alpine/musl@1.2.6-r2",
	)

	edge := nl.GetEdgeByType(img.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge, "image node should contain the packages")
	assert.ElementsMatch(t,
		[]string{pkgsByName["musl"].GetId(), pkgsByName["busybox-binsh"].GetId()},
		edge.GetTo(),
	)
}

func TestExtractSingleArchIncludeFiles(t *testing.T) {
	t.Parallel()

	host := startRegistry(t)
	refStr, _ := pushTestImage(t, host)

	u := NewUnpacker()
	u.Options.IncludeFiles = true
	lists, err := u.Extract(t.Context(), &Reference{Ref: refStr})
	require.NoError(t, err)
	require.Len(t, lists, 1)

	// 1 image node + 2 packages + 2 musl file records (F:lib and the R:
	// loader file).
	var files []*sbom.Node
	for _, n := range lists[0].GetNodes() {
		if n.GetType() == sbom.Node_FILE {
			files = append(files, n)
		}
	}
	require.Len(t, files, 2)
}

// archImage builds a platform image carrying an apk database whose musl
// package reports the given apk architecture.
func archImage(t *testing.T, goArch, apkArch string) v1.Image {
	t.Helper()
	db := strings.ReplaceAll(apkDB, "A:x86_64", "A:"+apkArch)
	layer := makeLayer(t,
		dir("lib"), dir("lib/apk"), dir("lib/apk/db"),
		file("lib/apk/db/installed", db),
		dir("etc"),
		file("etc/os-release", alpineOSRelease),
	)
	img := makeImage(t, layer)
	img, err := mutate.ConfigFile(img, &v1.ConfigFile{Architecture: goArch, OS: "linux"})
	require.NoError(t, err)
	return img
}

func TestExtractMultiArch(t *testing.T) {
	t.Parallel()

	host := startRegistry(t)

	amd64 := archImage(t, "amd64", "x86_64")
	arm64 := archImage(t, "arm64", "aarch64")
	// A buildx-style attestation entry that must be skipped.
	attestation := makeImage(t, makeLayer(t, file("attestation.json", "{}")))

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd64, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
		}},
		mutate.IndexAddendum{Add: arm64, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: "arm64"},
		}},
		mutate.IndexAddendum{Add: attestation, Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		}},
	)

	refStr := host + "/test/multi:v1"
	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, idx))
	indexDigest, err := idx.Digest()
	require.NoError(t, err)

	u := NewUnpacker()
	lists, err := u.Extract(t.Context(), &Reference{Ref: refStr})
	require.NoError(t, err)
	require.Len(t, lists, 1)
	nl := lists[0]

	// One root: the index node, carrying the index digest and a purl
	// without an arch qualifier.
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	idxNode := roots[0]
	assert.Equal(t, refStr, idxNode.GetName())
	assert.Equal(t, "v1", idxNode.GetVersion())
	assert.Equal(t, "multi-arch image index", idxNode.GetDescription())
	assert.Equal(t, indexDigest.Hex, idxNode.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	idxPurl := idxNode.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	assert.NotContains(t, idxPurl, "arch=")
	assert.Contains(t, idxPurl, "tag=v1")

	// The index contains exactly the two platform images (no attestation).
	edge := nl.GetEdgeByType(idxNode.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 2)

	archNodes := map[string]*sbom.Node{} // arch purl qualifier -> node
	for _, id := range edge.GetTo() {
		n := nl.GetNodeByID(id)
		require.NotNil(t, n)
		purl := n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
		switch {
		case strings.Contains(purl, "arch=amd64"):
			archNodes["amd64"] = n
		case strings.Contains(purl, "arch=arm64"):
			archNodes["arm64"] = n
		}
	}
	require.Len(t, archNodes, 2)

	for goArch, apkArch := range map[string]string{"amd64": "x86_64", "arm64": "aarch64"} {
		archNode := archNodes[goArch]

		// Platform images are addressed by digest-pinned references: the
		// digest in the name, the hashes, and the purl version; no tag.
		assert.Contains(t, archNode.GetName(), "@sha256:")
		assert.Equal(t, "linux/"+goArch, archNode.GetDescription())
		digest := archNode.GetHashes()[int32(sbom.HashAlgorithm_SHA256)]
		assert.NotEmpty(t, digest)
		assert.Contains(t, archNode.GetName(), digest)
		purl := archNode.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
		assert.NotContains(t, purl, "tag=")

		// Each platform image contains its own packages, with the right
		// apk arch in their purls.
		pkgEdge := nl.GetEdgeByType(archNode.GetId(), sbom.Edge_contains)
		require.NotNil(t, pkgEdge, "platform image %s should contain packages", goArch)
		require.Len(t, pkgEdge.GetTo(), 2)
		var muslPurl string
		for _, id := range pkgEdge.GetTo() {
			n := nl.GetNodeByID(id)
			if n.GetName() == "musl" {
				muslPurl = n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
			}
		}
		assert.Contains(t, muslPurl, "arch="+apkArch, "musl purl for %s", goArch)
	}

	// Total: 1 index + 2 platform images + 2 packages each.
	assert.Len(t, nl.GetNodes(), 7)
}

func TestExtractIndexWithoutPlatformImages(t *testing.T) {
	t.Parallel()

	host := startRegistry(t)
	attestation := makeImage(t, makeLayer(t, file("attestation.json", "{}")))
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: attestation,
		Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
		},
	})
	refStr := host + "/test/empty-index:v1"
	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, idx))

	u := NewUnpacker()
	_, err = u.Extract(t.Context(), &Reference{Ref: refStr})
	require.ErrorContains(t, err, "no platform images")
}

func TestExtractRejectsOtherSubjects(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	_, err := u.Extract(t.Context(), &system.LocalSystem{})
	require.ErrorContains(t, err, "cannot process subject")
	_, err = u.Extract(t.Context(), nil)
	require.ErrorContains(t, err, "nil subject")
}

func TestExtractPerLayerNotImplemented(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	u.Options.Mode = ModePerLayer
	_, err := u.Extract(t.Context(), &Reference{Ref: "example.com/a:b"})
	require.ErrorContains(t, err, "not implemented")
}

func TestOciPurl(t *testing.T) {
	t.Parallel()
	ref, err := name.ParseReference("ghcr.io/carabiner-dev/unpack:v1.2.3")
	require.NoError(t, err)
	digest := v1.Hash{Algorithm: "sha256", Hex: "abc123"}

	purl := ociPurl(ref, digest, "arm64")
	assert.Equal(t,
		"pkg:oci/unpack@sha256%3Aabc123?"+
			"arch=arm64&repository_url="+url.QueryEscape("ghcr.io/carabiner-dev/unpack")+"&tag=v1.2.3",
		purl,
	)
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildArchiveImage assembles the same minimal apk image the registry
// tests use, without pushing it anywhere.
func buildArchiveImage(t *testing.T, osRelease string, extraLayers ...v1.Layer) v1.Image {
	t.Helper()
	layer := makeLayer(t,
		dir("lib"), dir("lib/apk"), dir("lib/apk/db"),
		file("lib/apk/db/installed", apkDB),
		dir("etc"),
		file("etc/os-release", osRelease),
	)
	img := makeImage(t, append([]v1.Layer{layer}, extraLayers...)...)
	// The config is edited in place: replacing it wholesale would drop
	// the rootfs diff_ids, which the tarball loader validates.
	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.Architecture = "amd64"
	cfg.OS = "linux"
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

func TestExtractArchive(t *testing.T) {
	t.Parallel()

	img := buildArchiveImage(t, alpineOSRelease)
	digest, err := img.Digest()
	require.NoError(t, err)
	tag, err := name.NewTag("registry.example.com/test/minialpine:v1")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.MultiWriteToFile(path, map[name.Tag]v1.Image{tag: img}))

	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"identity from repotags", ""},
		{"explicit ref", tag.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u := NewUnpacker()
			lists, err := u.Extract(t.Context(), &Reference{Ref: tc.ref, Archive: path})
			require.NoError(t, err)
			require.Len(t, lists, 1)
			nl := lists[0]

			roots := nl.GetRootNodes()
			require.Len(t, roots, 1)
			node := roots[0]

			assert.Equal(t, tag.String(), node.GetName())
			assert.Equal(t, "v1", node.GetVersion())
			assert.Equal(t, "linux/amd64", node.GetDescription())
			assert.Equal(t, digest.Hex, node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
			assert.Contains(t,
				node.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
				"pkg:oci/minialpine",
			)

			edge := nl.GetEdgeByType(node.GetId(), sbom.Edge_contains)
			require.NotNil(t, edge)
			assert.Len(t, edge.GetTo(), 2, "both apk packages hang off the image")
		})
	}
}

func TestExtractArchiveRecordLayers(t *testing.T) {
	t.Parallel()

	extra := makeLayer(t, dir("usr"), file("usr/hello.txt", "hello"))
	img := buildArchiveImage(t, alpineOSRelease, extra)
	layers, err := img.Layers()
	require.NoError(t, err)
	require.Len(t, layers, 2)
	wantDiffIDs := make([]string, 0, len(layers))
	for _, layer := range layers {
		diffID, err := layer.DiffID()
		require.NoError(t, err)
		wantDiffIDs = append(wantDiffIDs, diffID.String())
	}

	tag, err := name.NewTag("registry.example.com/test/layered:v1")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.MultiWriteToFile(path, map[name.Tag]v1.Image{tag: img}))

	u := NewUnpacker()
	u.Options.RecordLayers = true
	lists, err := u.Extract(t.Context(), &Reference{Archive: path})
	require.NoError(t, err)
	nl := lists[0]
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	imageID := roots[0].GetId()

	// Everything hanging directly off the image node: the system
	// packages plus one structural node per layer.
	contained := []string{}
	for _, edge := range nl.GetEdges() {
		if edge.GetFrom() == imageID && edge.GetType() == sbom.Edge_contains {
			contained = append(contained, edge.GetTo()...)
		}
	}

	layerNames := []string{}
	packages := 0
	for _, id := range contained {
		node := nl.GetNodeByID(id)
		require.NotNil(t, node)
		if !strings.HasPrefix(node.GetName(), "sha256:") {
			packages++
			continue
		}
		layerNames = append(layerNames, node.GetName())
		assert.Equal(t, strings.TrimPrefix(node.GetName(), "sha256:"),
			node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
		for _, edge := range nl.GetEdges() {
			assert.NotEqual(t, id, edge.GetFrom(), "layer nodes carry no packages")
		}
	}
	assert.Equal(t, wantDiffIDs, layerNames, "one node per layer, in order")
	assert.Equal(t, 2, packages, "the apk packages still hang off the image")
}

func TestExtractArchiveUntagged(t *testing.T) {
	t.Parallel()

	img := buildArchiveImage(t, alpineOSRelease)
	digest, err := img.Digest()
	require.NoError(t, err)
	dref, err := name.NewDigest("registry.example.com/test/minialpine@" + digest.String())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.MultiRefWriteToFile(path, map[name.Reference]v1.Image{dref: img}))

	u := NewUnpacker()
	lists, err := u.Extract(t.Context(), &Reference{Archive: path})
	require.NoError(t, err)
	require.Len(t, lists, 1)

	roots := lists[0].GetRootNodes()
	require.Len(t, roots, 1)
	node := roots[0]

	assert.Equal(t, digest.String(), node.GetName(),
		"untagged archives identify through the image digest")
	assert.Empty(t, node.GetVersion())
	assert.Empty(t, node.GetIdentifiers(), "no reference, no purl")
	assert.Equal(t, digest.Hex, node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
}

func TestExtractArchiveMultiImage(t *testing.T) {
	t.Parallel()

	one := buildArchiveImage(t, alpineOSRelease)
	two := buildArchiveImage(t, "ID=alpine\nVERSION_ID=3.25.0\n")
	tagOne, err := name.NewTag("registry.example.com/test/one:v1")
	require.NoError(t, err)
	tagTwo, err := name.NewTag("registry.example.com/test/two:v1")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "images.tar")
	require.NoError(t, tarball.MultiWriteToFile(path, map[name.Tag]v1.Image{
		tagOne: one,
		tagTwo: two,
	}))

	u := NewUnpacker()

	_, err = u.Extract(t.Context(), &Reference{Archive: path})
	require.ErrorContains(t, err, "set Ref to select one")

	lists, err := u.Extract(t.Context(), &Reference{Ref: tagTwo.String(), Archive: path})
	require.NoError(t, err)
	roots := lists[0].GetRootNodes()
	require.Len(t, roots, 1)
	assert.Equal(t, tagTwo.String(), roots[0].GetName())

	_, err = u.Extract(t.Context(), &Reference{
		Ref:     "registry.example.com/test/absent:v1",
		Archive: path,
	})
	require.Error(t, err, "refs not present in the archive fail")
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package apk

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system/internal/osrelease"
)

func TestApkPurl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pkg  apkPackage
		osr  osrelease.Data
		want string
	}{
		{
			name: "basic alpine package",
			pkg: apkPackage{
				Name: "musl", Version: "1.2.6-r2", Arch: "x86_64", Origin: "musl",
			},
			osr:  osrelease.Data{ID: "alpine", VersionID: "3.24.0"},
			want: "pkg:apk/alpine/musl@1.2.6-r2?arch=x86_64&distro=alpine-3.24.0",
		},
		{
			name: "subpackage gets an upstream qualifier",
			pkg: apkPackage{
				Name: "busybox-binsh", Version: "1.37.0-r30", Arch: "x86_64",
				Origin: "busybox",
			},
			osr:  osrelease.Data{ID: "alpine", VersionID: "3.24.0"},
			want: "pkg:apk/alpine/busybox-binsh@1.37.0-r30?arch=x86_64&distro=alpine-3.24.0&upstream=busybox",
		},
		{
			name: "name and namespace lowercased",
			pkg: apkPackage{
				Name: "Musl", Version: "1.2.6-r2", Arch: "X86_64",
			},
			osr:  osrelease.Data{ID: "Alpine", VersionID: "3.24.0"},
			want: "pkg:apk/alpine/musl@1.2.6-r2?arch=x86_64&distro=alpine-3.24.0",
		},
		{
			name: "no os-release info: namespace and distro omitted",
			pkg: apkPackage{
				Name: "musl", Version: "1.2.6-r2", Arch: "x86_64",
			},
			osr:  osrelease.Data{},
			want: "pkg:apk/musl@1.2.6-r2?arch=x86_64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, apkPurl(&tc.pkg, tc.osr))
		})
	}
}

func TestExtractFromFS_NoDB(t *testing.T) {
	t.Parallel()
	d := New()
	nl, err := d.ExtractFromFS(fstest.MapFS{
		"etc/os-release": &fstest.MapFile{Data: []byte("ID=alpine\nVERSION_ID=3.24.0\n")},
	}, nil)
	require.NoError(t, err)
	assert.Nil(t, nl, "no apk database should yield (nil, nil)")
}

// TestExtractFromFS_Alpine runs the full ExtractFromFS path against the
// testdata/alpine324 fixture: the verbatim apk installed database and
// os-release of an alpine:3.24 image.
func TestExtractFromFS_Alpine(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS("testdata/alpine324")

	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	nodes := nl.GetNodes()
	require.Len(t, nodes, 16, "IncludeFiles defaults to false, so we expect only package nodes")

	byName := map[string]*sbom.Node{}
	for _, n := range nodes {
		byName[n.GetName()] = n
	}

	musl := byName["musl"]
	require.NotNil(t, musl)
	assert.Equal(t, "1.2.6-r2", musl.GetVersion())
	assert.Equal(t, "the musl c library (libc) implementation", musl.GetSummary())
	assert.Equal(t, "https://musl.libc.org/", musl.GetUrlHome())
	assert.Equal(t, []string{"MIT"}, musl.GetLicenses())

	if assert.Len(t, musl.GetSuppliers(), 1) {
		assert.Equal(t, "Natanael Copa", musl.GetSuppliers()[0].GetName())
		assert.Equal(t, "ncopa@alpinelinux.org", musl.GetSuppliers()[0].GetEmail())
	}

	// The C: identity checksum lands as the package's SHA1.
	assert.Equal(t,
		"0f7e5827e4e1a73631beda27b78431a8ba240e05",
		musl.GetHashes()[int32(sbom.HashAlgorithm_SHA1)],
	)

	assert.Equal(t,
		"pkg:apk/alpine/musl@1.2.6-r2?arch=x86_64&distro=alpine-3.24.0",
		musl.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)

	// Subpackage: origin differs from name and becomes the upstream
	// qualifier.
	binsh := byName["busybox-binsh"]
	require.NotNil(t, binsh)
	assert.Contains(t,
		binsh.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
		"upstream=busybox",
	)
}

// TestExtractFromFS_AlpineIncludeFiles flips IncludeFiles on and verifies
// the F:/R:/Z: records expand into file nodes.
func TestExtractFromFS_AlpineIncludeFiles(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS("testdata/alpine324")

	nl, err := d.ExtractFromFS(source, &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	require.NotNil(t, nl)

	// 16 packages + 110 file records (R: entries; F: directories are
	// not emitted).
	require.Len(t, nl.GetNodes(), 126)

	// Spot-check the musl loader file and its digest from the Z: record.
	var loader *sbom.Node
	for _, n := range nl.GetNodes() {
		if n.GetType() != sbom.Node_FILE {
			continue
		}
		assert.NotEmpty(t, n.GetHashes(), "R: file records should carry Z: digests: %s", n.GetName())
		if n.GetName() == "/lib/libc.musl-x86_64.so.1" {
			loader = n
		}
	}
	require.NotNil(t, loader, "musl loader file node missing")
	assert.Equal(t,
		"ef2277245372a40e26c61249af4a2ee82cec2552",
		loader.GetHashes()[int32(sbom.HashAlgorithm_SHA1)],
	)
}

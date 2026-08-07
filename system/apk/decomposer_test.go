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
		{
			name: "no version",
			pkg: apkPackage{
				Name: "musl", Arch: "x86_64",
			},
			osr:  osrelease.Data{ID: "alpine", VersionID: "3.24.0"},
			want: "pkg:apk/alpine/musl?arch=x86_64&distro=alpine-3.24.0",
		},
		{
			// '+' is reserved by the purl spec and must be percent-encoded
			// as %2B in every component, or string-matching consumers
			// (vulnerability scanners) miss the package.
			name: "plus signs percent-encoded in name and version",
			pkg: apkPackage{
				Name: "libstdc++", Version: "14.3.0+git-r2", Arch: "x86_64",
				Origin: "gcc+patched",
			},
			osr: osrelease.Data{ID: "alpine", VersionID: "3.24.0"},
			want: "pkg:apk/alpine/libstdc%2B%2B@14.3.0%2Bgit-r2?" +
				"arch=x86_64&distro=alpine-3.24.0&upstream=gcc%2Bpatched",
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

	// Alpine mirrors are not derivable from the installed database, so no
	// download location is synthesized for them.
	for _, n := range nodes {
		assert.Empty(t, n.GetUrlDownload(),
			"alpine packages must not get a guessed download location: %s", n.GetName())
	}

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

func TestApkDownloadLocation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pkg  apkPackage
		osr  osrelease.Data
		want string
	}{
		{
			name: "wolfi package gets the well-known host",
			pkg: apkPackage{
				Name: "glibc", Version: "2.41-r3", Arch: "x86_64",
			},
			osr:  osrelease.Data{ID: "wolfi", VersionID: "20230201"},
			want: "https://packages.wolfi.dev/os/x86_64/glibc-2.41-r3.apk",
		},
		{
			name: "wolfi id is matched case-insensitively",
			pkg: apkPackage{
				Name: "glibc", Version: "2.41-r3", Arch: "aarch64",
			},
			osr:  osrelease.Data{ID: "Wolfi", VersionID: "20230201"},
			want: "https://packages.wolfi.dev/os/aarch64/glibc-2.41-r3.apk",
		},
		{
			name: "alpine gets none: its mirrors are not derivable",
			pkg: apkPackage{
				Name: "musl", Version: "1.2.6-r2", Arch: "x86_64",
			},
			osr:  osrelease.Data{ID: "alpine", VersionID: "3.24.0"},
			want: "",
		},
		{
			name: "no os-release: none",
			pkg: apkPackage{
				Name: "musl", Version: "1.2.6-r2", Arch: "x86_64",
			},
			osr:  osrelease.Data{},
			want: "",
		},
		{
			name: "wolfi without arch: none",
			pkg: apkPackage{
				Name: "glibc", Version: "2.41-r3",
			},
			osr:  osrelease.Data{ID: "wolfi", VersionID: "20230201"},
			want: "",
		},
		{
			name: "wolfi without version: none",
			pkg: apkPackage{
				Name: "glibc", Arch: "x86_64",
			},
			osr:  osrelease.Data{ID: "wolfi", VersionID: "20230201"},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, apkDownloadLocation(&tc.pkg, tc.osr))
		})
	}
}

// TestExtractFromFS_Wolfi drives the full path over a synthetic Wolfi system
// root: Wolfi is the only apk distro whose download locations we synthesize.
func TestExtractFromFS_Wolfi(t *testing.T) {
	t.Parallel()
	d := New()
	nl, err := d.ExtractFromFS(fstest.MapFS{
		"etc/os-release": &fstest.MapFile{
			Data: []byte("ID=wolfi\nNAME=\"Wolfi\"\nVERSION_ID=20230201\n"),
		},
		"lib/apk/db/installed": &fstest.MapFile{Data: []byte(
			"C:Q1D1L4TGN2vT+ZBmpKtWDXwLmVGgg=\n" +
				"P:glibc\n" +
				"V:2.41-r3\n" +
				"A:x86_64\n" +
				"T:the GNU C library\n" +
				"o:glibc\n" +
				"\n" +
				"C:Q1yNZ7cLzTIYSHZ2Wj5vAlZzWuKmA=\n" +
				"P:libstdc++\n" +
				"V:14.2.0-r6\n" +
				"A:x86_64\n" +
				"o:gcc\n" +
				"\n",
		)},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	byName := map[string]*sbom.Node{}
	for _, n := range nl.GetNodes() {
		byName[n.GetName()] = n
	}
	require.Len(t, byName, 2)

	glibc := byName["glibc"]
	require.NotNil(t, glibc)
	assert.Equal(t,
		"pkg:apk/wolfi/glibc@2.41-r3?arch=x86_64&distro=wolfi-20230201",
		glibc.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)
	assert.Equal(t,
		"https://packages.wolfi.dev/os/x86_64/glibc-2.41-r3.apk",
		glibc.GetUrlDownload(),
	)

	// The '+' in the name is percent-encoded in the purl but stays literal
	// in the download URL, which is a plain path.
	stdcpp := byName["libstdc++"]
	require.NotNil(t, stdcpp)
	assert.Equal(t,
		"pkg:apk/wolfi/libstdc%2B%2B@14.2.0-r6?arch=x86_64&distro=wolfi-20230201&upstream=gcc",
		stdcpp.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)
	assert.Equal(t,
		"https://packages.wolfi.dev/os/x86_64/libstdc++-14.2.0-r6.apk",
		stdcpp.GetUrlDownload(),
	)
}

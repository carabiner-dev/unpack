// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"testing"
	"testing/fstest"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/unpack/system/internal/osrelease"
)

func TestDebPurl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pkg  dpkgPackage
		osr  osrelease.Data
		want string
	}{
		{
			name: "basic debian package",
			pkg: dpkgPackage{
				Name: "curl", Version: "7.74.0-1.3+deb11u7", Architecture: "amd64",
			},
			osr:  osrelease.Data{ID: "debian", VersionID: "11"},
			want: "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
		},
		{
			name: "epoch travels inside the version",
			pkg: dpkgPackage{
				Name: "dpkg", Version: "1:1.20.12", Architecture: "amd64",
			},
			osr:  osrelease.Data{ID: "debian", VersionID: "11"},
			want: "pkg:deb/debian/dpkg@1:1.20.12?arch=amd64&distro=debian-11",
		},
		{
			name: "upstream qualifier from source field",
			pkg: dpkgPackage{
				Name: "libc6", Version: "2.31-13+deb11u6", Architecture: "amd64",
				Source: "glibc",
			},
			osr:  osrelease.Data{ID: "debian", VersionID: "11"},
			want: "pkg:deb/debian/libc6@2.31-13+deb11u6?arch=amd64&distro=debian-11&upstream=glibc",
		},
		{
			name: "upstream carries the source version",
			pkg: dpkgPackage{
				Name: "base-files", Version: "11.1+deb11u7", Architecture: "amd64",
				Source: "base-files", SourceVersion: "11.1+deb11u6",
			},
			osr:  osrelease.Data{ID: "debian", VersionID: "11"},
			want: "pkg:deb/debian/base-files@11.1+deb11u7?arch=amd64&distro=debian-11&upstream=base-files%4011.1%2Bdeb11u6",
		},
		{
			name: "ubuntu namespace",
			pkg: dpkgPackage{
				Name: "libssl3", Version: "3.0.2-0ubuntu1.10", Architecture: "amd64",
				Source: "openssl",
			},
			osr:  osrelease.Data{ID: "ubuntu", VersionID: "22.04"},
			want: "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04&upstream=openssl",
		},
		{
			name: "name lowercased and namespace lowercased",
			pkg: dpkgPackage{
				Name: "Curl", Version: "7.74.0-1", Architecture: "ARM64",
			},
			osr:  osrelease.Data{ID: "Debian", VersionID: "11"},
			want: "pkg:deb/debian/curl@7.74.0-1?arch=arm64&distro=debian-11",
		},
		{
			name: "no os-release info: namespace and distro omitted",
			pkg: dpkgPackage{
				Name: "curl", Version: "7.74.0-1", Architecture: "amd64",
			},
			osr:  osrelease.Data{},
			want: "pkg:deb/curl@7.74.0-1?arch=amd64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, debPurl(&tc.pkg, tc.osr))
		})
	}
}

const libcStanza = `Package: libc6
Status: install ok installed
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: amd64
Source: glibc
Version: 2.31-13+deb11u6
Description: GNU C Library: Shared libraries
Homepage: https://www.gnu.org/software/libc/libc.html
`

const removedStanza = `Package: tzdata
Status: deinstall ok config-files
Architecture: all
Version: 2021a-1+deb11u10
Description: time zone and daylight-saving time data
`

const debianOSRelease = `ID=debian
VERSION_ID="11"
`

func TestExtractFromFS_StatusFile(t *testing.T) {
	t.Parallel()
	source := fstest.MapFS{
		"var/lib/dpkg/status": &fstest.MapFile{
			Data: []byte(libcStanza + "\n" + removedStanza),
		},
		"etc/os-release": &fstest.MapFile{Data: []byte(debianOSRelease)},
	}

	d := New()
	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// The removed package is filtered out.
	nodes := nl.GetNodes()
	require.Len(t, nodes, 1)

	n := nodes[0]
	assert.Equal(t, "libc6", n.GetName())
	assert.Equal(t, "2.31-13+deb11u6", n.GetVersion())
	assert.Equal(t, "GNU C Library: Shared libraries", n.GetSummary())
	assert.Equal(t, "https://www.gnu.org/software/libc/libc.html", n.GetUrlHome())
	assert.Equal(t,
		"pkg:deb/debian/libc6@2.31-13+deb11u6?arch=amd64&distro=debian-11&upstream=glibc",
		n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)

	if assert.Len(t, n.GetSuppliers(), 1) {
		assert.Equal(t, "GNU Libc Maintainers", n.GetSuppliers()[0].GetName())
		assert.Equal(t, "debian-glibc@lists.debian.org", n.GetSuppliers()[0].GetEmail())
		assert.True(t, n.GetSuppliers()[0].GetIsOrg())
	}
}

func TestExtractFromFS_StatusDir(t *testing.T) {
	t.Parallel()
	// Distroless layout: per-package stanzas (no Status field) plus md5sums
	// companions that must be skipped.
	source := fstest.MapFS{
		"var/lib/dpkg/status.d/base-files": &fstest.MapFile{
			Data: []byte(`Package: base-files
Version: 11.1+deb11u7
Architecture: amd64
Description: Debian base system miscellaneous files
`),
		},
		"var/lib/dpkg/status.d/base-files.md5sums": &fstest.MapFile{
			Data: []byte("bbc8c6a09a87423a4a4cb43c1c9a9d49  etc/debian_version\n"),
		},
		"var/lib/dpkg/status.d/netbase": &fstest.MapFile{
			Data: []byte(`Package: netbase
Version: 6.3
Architecture: all
Description: Basic TCP/IP networking system
`),
		},
		"etc/os-release": &fstest.MapFile{Data: []byte(debianOSRelease)},
	}

	d := New()
	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	nodes := nl.GetNodes()
	require.Len(t, nodes, 2)

	byName := map[string]string{}
	for _, n := range nodes {
		byName[n.GetName()] = n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	}
	assert.Equal(t,
		"pkg:deb/debian/base-files@11.1+deb11u7?arch=amd64&distro=debian-11",
		byName["base-files"],
	)
	assert.Equal(t,
		"pkg:deb/debian/netbase@6.3?arch=all&distro=debian-11",
		byName["netbase"],
	)
}

func TestExtractFromFS_NoDB(t *testing.T) {
	t.Parallel()
	d := New()
	nl, err := d.ExtractFromFS(fstest.MapFS{
		"etc/os-release": &fstest.MapFile{Data: []byte(debianOSRelease)},
	}, nil)
	require.NoError(t, err)
	assert.Nil(t, nl, "no dpkg database should yield (nil, nil)")
}

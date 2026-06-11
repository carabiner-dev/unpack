// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rpm

import (
	"os"
	"testing"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system/internal/osrelease"
)

func intPtr(v int) *int { return &v }

func TestRpmPurl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pkg  rpmdb.PackageInfo
		osr  osrelease.Data
		want string
	}{
		{
			name: "spec example: curl on fedora 25",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1.fc25", Arch: "i386",
			},
			osr:  osrelease.Data{ID: "fedora", VersionID: "25"},
			want: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
		},
		{
			name: "epoch becomes a qualifier",
			pkg: rpmdb.PackageInfo{
				Name: "centerim", Version: "4.22.10", Release: "1.el6",
				Arch: "i686", Epoch: intPtr(1),
			},
			osr:  osrelease.Data{ID: "fedora", VersionID: "25"},
			want: "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&distro=fedora-25&epoch=1",
		},
		{
			name: "epoch zero is omitted",
			pkg: rpmdb.PackageInfo{
				Name: "bash", Version: "5.2.15", Release: "1.fc38",
				Arch: "x86_64", Epoch: intPtr(0),
			},
			osr:  osrelease.Data{ID: "fedora", VersionID: "38"},
			want: "pkg:rpm/fedora/bash@5.2.15-1.fc38?arch=x86_64&distro=fedora-38",
		},
		{
			name: "upstream qualifier from source rpm",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1.fc26", Arch: "x86_64",
				SourceRpm: "curl-7.50.3-1.fc26.src.rpm",
			},
			osr:  osrelease.Data{ID: "fedora", VersionID: "26"},
			want: "pkg:rpm/fedora/curl@7.50.3-1.fc26?arch=x86_64&distro=fedora-26&upstream=curl-7.50.3-1.fc26.src.rpm",
		},
		{
			name: "namespace lowercased",
			pkg: rpmdb.PackageInfo{
				Name: "openssl", Version: "3.0.7", Release: "18.el9_2",
				Arch: "x86_64",
			},
			osr:  osrelease.Data{ID: "RHEL", VersionID: "9.2"},
			want: "pkg:rpm/rhel/openssl@3.0.7-18.el9_2?arch=x86_64&distro=rhel-9.2",
		},
		{
			name: "arch lowercased",
			pkg: rpmdb.PackageInfo{
				Name: "kernel", Version: "6.4.6", Release: "200.fc38", Arch: "X86_64",
			},
			osr:  osrelease.Data{ID: "fedora", VersionID: "38"},
			want: "pkg:rpm/fedora/kernel@6.4.6-200.fc38?arch=x86_64&distro=fedora-38",
		},
		{
			name: "modularitylabel encoded",
			pkg: rpmdb.PackageInfo{
				Name: "nodejs", Version: "14.21.3", Release: "1.module_f38+18119+78d34c93",
				Arch:            "x86_64",
				Modularitylabel: "nodejs:14:8060020220421152133:e6e4d6a4",
			},
			osr:  osrelease.Data{ID: "fedora", VersionID: "38"},
			want: "pkg:rpm/fedora/nodejs@14.21.3-1.module_f38+18119+78d34c93?arch=x86_64&distro=fedora-38&modularitylabel=nodejs%3A14%3A8060020220421152133%3Ae6e4d6a4",
		},
		{
			name: "no os-release info: namespace and distro omitted",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1", Arch: "x86_64",
			},
			osr:  osrelease.Data{},
			want: "pkg:rpm/curl@7.50.3-1?arch=x86_64",
		},
		{
			name: "qualifiers sorted alphabetically",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1.fc26", Arch: "x86_64",
				Epoch: intPtr(2), SourceRpm: "curl-7.50.3-1.fc26.src.rpm",
			},
			osr: osrelease.Data{ID: "fedora", VersionID: "26"},
			// arch < distro < epoch < upstream
			want: "pkg:rpm/fedora/curl@7.50.3-1.fc26?arch=x86_64&distro=fedora-26&epoch=2&upstream=curl-7.50.3-1.fc26.src.rpm",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rpmPurl(&tc.pkg, tc.osr)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPackagesToNodeListMapping(t *testing.T) {
	t.Parallel()
	pkgs := []*rpmdb.PackageInfo{
		{
			Name: "curl", Version: "7.50.3", Release: "1.fc25", Arch: "x86_64",
			License: "MIT",
			Vendor:  "Fedora Project",
			Summary: "A utility for getting files from remote servers",
			SigMD5:  "d41d8cd98f00b204e9800998ecf8427e",
		},
	}
	nl, err := packagesToNodeList(pkgs, osrelease.Data{ID: "fedora", VersionID: "25"}, false)
	require.NoError(t, err)

	nodes := nl.GetNodes()
	if assert.Len(t, nodes, 1) {
		n := nodes[0]
		assert.Equal(t, "curl", n.GetName())
		assert.Equal(t, "7.50.3-1.fc25", n.GetVersion())
		assert.Equal(t, "A utility for getting files from remote servers", n.GetSummary())
		assert.Equal(t, []string{"MIT"}, n.GetLicenses())

		if assert.Len(t, n.GetSuppliers(), 1) {
			assert.Equal(t, "Fedora Project", n.GetSuppliers()[0].GetName())
			assert.True(t, n.GetSuppliers()[0].GetIsOrg())
		}

		assert.Equal(t,
			"d41d8cd98f00b204e9800998ecf8427e",
			n.GetHashes()[int32(sbom.HashAlgorithm_MD5)],
		)
	}
}

func TestPackagesToNodeListSkipsGPGPubkey(t *testing.T) {
	t.Parallel()
	pkgs := []*rpmdb.PackageInfo{
		{Name: "gpg-pubkey", Version: "fd431d51", Release: "4ae0493b"},
		{Name: "curl", Version: "7.50.3", Release: "1.fc25"},
	}
	nl, err := packagesToNodeList(pkgs, osrelease.Data{}, false)
	require.NoError(t, err)
	nodes := nl.GetNodes()
	if assert.Len(t, nodes, 1) {
		assert.Equal(t, "curl", nodes[0].GetName())
	}
}

// TestExtractFromFS_BDB runs the full ExtractFromFS path against the
// testdata/rhel8-libuuid fixture — a BerkeleyDB-format Packages file with a
// single libuuid package, plus a matching etc/os-release. The single-package
// fixture is enough to validate every step of the chain: BDB stage+open,
// os-release parsing, purl construction, and the rich Node fields.
func TestExtractFromFS_BDB(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS("testdata/rhel8-libuuid")

	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	nodes := nl.GetNodes()
	require.Len(t, nodes, 1, "IncludeFiles defaults to false, so we expect only the package node")

	n := nodes[0]
	assert.Equal(t, "libuuid", n.GetName())
	assert.Equal(t, "2.32.1-42.el8_8", n.GetVersion())
	assert.Equal(t, []string{"BSD"}, n.GetLicenses())

	if assert.Len(t, n.GetSuppliers(), 1) {
		assert.Equal(t, "Red Hat, Inc.", n.GetSuppliers()[0].GetName())
		assert.True(t, n.GetSuppliers()[0].GetIsOrg())
	}

	assert.Equal(t,
		"c1e561f13d39aee443a1f00258fba000",
		n.GetHashes()[int32(sbom.HashAlgorithm_MD5)],
	)

	// Namespace and distro come from etc/os-release; upstream from SourceRpm.
	assert.Equal(t,
		"pkg:rpm/rhel/libuuid@2.32.1-42.el8_8?arch=x86_64&distro=rhel-8.8&upstream=util-linux-2.32.1-42.el8_8.src.rpm",
		n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)
}

// TestExtractFromFS_BDB_IncludeFiles flips IncludeFiles on and verifies that
// the libuuid package now contains the seven file entries the fixture
// declares, that paths reassemble correctly, and that real digests get
// labelled with the package's DigestAlgorithm (SHA-256 for this RPM).
func TestExtractFromFS_BDB_IncludeFiles(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS("testdata/rhel8-libuuid")

	nl, err := d.ExtractFromFS(source, &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	require.NotNil(t, nl)

	// 1 package + 5 files (the two directories the package owns are not
	// part of the file list)
	nodes := nl.GetNodes()
	require.Len(t, nodes, 6)

	// Index by name so we can assert by file path independent of ordering.
	byName := map[string]*sbom.Node{}
	var pkgNode *sbom.Node
	for _, n := range nodes {
		if n.GetType() == sbom.Node_PACKAGE {
			pkgNode = n
			continue
		}
		byName[n.GetName()] = n
	}
	require.NotNil(t, pkgNode)

	// Spot-check the expected paths: symlinks (no digest) and the .so
	// with a SHA-256 digest; directories are filtered out.
	for _, want := range []string{
		"/usr/lib/.build-id/df/ef6a880adac817216ab9866779a0725e017647",
		"/usr/lib64/libuuid.so.1",
		"/usr/lib64/libuuid.so.1.3.0",
		"/usr/share/licenses/libuuid/COPYING",
		"/usr/share/licenses/libuuid/COPYING.BSD-3",
	} {
		_, ok := byName[want]
		assert.True(t, ok, "missing file node %q", want)
	}

	// Real-file digests get labelled with the algorithm the package
	// declares (SHA-256 for libuuid).
	so := byName["/usr/lib64/libuuid.so.1.3.0"]
	require.NotNil(t, so)
	assert.Equal(t,
		"3c8f59a0e39cce53501045859f5c9a86b82fedd558a2f4110ab1823047b43745",
		so.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
	)

	// Files without a digest (directories, symlinks) get a node but no
	// Hashes map entry.
	link := byName["/usr/lib64/libuuid.so.1"]
	require.NotNil(t, link)
	assert.Empty(t, link.GetHashes())

	// Every file node has a contains-edge from the package; verify by
	// counting outgoing contains-edges on the package.
	var fileEdges int
	for _, e := range nl.GetEdges() {
		if e.GetFrom() == pkgNode.GetId() && e.GetType() == sbom.Edge_contains {
			fileEdges += len(e.GetTo())
		}
	}
	assert.Equal(t, 5, fileEdges)
}

func TestMapDigestAlgorithm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in     rpmdb.DigestAlgorithm
		want   sbom.HashAlgorithm
		mapped bool
	}{
		{rpmdb.PGPHASHALGO_MD5, sbom.HashAlgorithm_MD5, true},
		{rpmdb.PGPHASHALGO_SHA1, sbom.HashAlgorithm_SHA1, true},
		{rpmdb.PGPHASHALGO_MD2, sbom.HashAlgorithm_MD2, true},
		{rpmdb.PGPHASHALGO_SHA256, sbom.HashAlgorithm_SHA256, true},
		{rpmdb.PGPHASHALGO_SHA384, sbom.HashAlgorithm_SHA384, true},
		{rpmdb.PGPHASHALGO_SHA512, sbom.HashAlgorithm_SHA512, true},
		{rpmdb.PGPHASHALGO_SHA224, sbom.HashAlgorithm_SHA224, true},
		// Algorithms protobom doesn't model: RIPEMD160 (3), TIGER192 (6),
		// HAVAL_5_160 (7). Dropping them is preferable to mislabelling them.
		{rpmdb.PGPHASHALGO_RIPEMD160, sbom.HashAlgorithm_UNKNOWN, false},
		{rpmdb.PGPHASHALGO_TIGER192, sbom.HashAlgorithm_UNKNOWN, false},
		{rpmdb.PGPHASHALGO_HAVAL_5_160, sbom.HashAlgorithm_UNKNOWN, false},
	} {
		got, ok := mapDigestAlgorithm(tc.in)
		assert.Equal(t, tc.mapped, ok, "algorithm %d mapped?", tc.in)
		assert.Equal(t, tc.want, got, "algorithm %d result", tc.in)
	}
}

// TestExtractFromFS_NoDB verifies that a filesystem without an RPM database
// returns (nil, nil) rather than an error — RPM is not the only system
// package format and its absence isn't a failure.
func TestExtractFromFS_NoDB(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS(t.TempDir())

	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	assert.Nil(t, nl)
}

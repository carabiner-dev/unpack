// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"testing"
	"testing/fstest"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// fixtureFS loads a tar.gz fixture into an in-memory filesystem. The
// debian13-slim fixture ships as a tarball because its multi-arch dpkg info
// files have colons in their names ("libc6:amd64.list"), which NTFS forbids:
// keeping them as plain files would break git checkout on Windows.
func fixtureFS(t *testing.T, tarPath string) fs.FS {
	t.Helper()

	f, err := os.Open(tarPath)
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck // read-only file

	gz, err := gzip.NewReader(f)
	require.NoError(t, err)

	fsys := fstest.MapFS{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		fsys[path.Clean(hdr.Name)] = &fstest.MapFile{Data: data}
	}
	return fsys
}

// TestExtractFromFS_DebianSlim runs the full ExtractFromFS path against the
// testdata/debian13-slim fixture: a dpkg status file lifted from
// debian:stable-slim, trimmed to base-files and libc6 plus a
// removed-but-not-purged sed stanza, with the real info/ companions and
// etc/os-release.
func TestExtractFromFS_DebianSlim(t *testing.T) {
	t.Parallel()
	d := New()
	source := fixtureFS(t, "testdata/debian13-slim.tar.gz")

	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// The sed ghost (deinstall ok config-files) is filtered out.
	nodes := nl.GetNodes()
	require.Len(t, nodes, 2, "IncludeFiles defaults to false, so we expect only package nodes")

	byName := map[string]*sbom.Node{}
	for _, n := range nodes {
		byName[n.GetName()] = n
	}
	require.NotContains(t, byName, "sed")

	libc := byName["libc6"]
	require.NotNil(t, libc)
	assert.Equal(t, "2.41-12+deb13u3", libc.GetVersion())
	assert.Equal(t, "GNU C Library: Shared libraries", libc.GetSummary())
	assert.Equal(t, "https://www.gnu.org/software/libc/libc.html", libc.GetUrlHome())

	if assert.Len(t, libc.GetSuppliers(), 1) {
		assert.Equal(t, "GNU Libc Maintainers", libc.GetSuppliers()[0].GetName())
		assert.Equal(t, "debian-glibc@lists.debian.org", libc.GetSuppliers()[0].GetEmail())
	}

	// Namespace and distro come from etc/os-release; upstream from Source.
	assert.Equal(t,
		"pkg:deb/debian/libc6@2.41-12+deb13u3?arch=amd64&distro=debian-13&upstream=glibc",
		libc.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)
}

// TestExtractFromFS_DebianSlimIncludeFiles flips IncludeFiles on and checks
// the file lists assemble from the info/ directory: base-files registers
// under its plain name, libc6 under the multi-arch "libc6:amd64" name.
func TestExtractFromFS_DebianSlimIncludeFiles(t *testing.T) {
	t.Parallel()
	d := New()
	source := fixtureFS(t, "testdata/debian13-slim.tar.gz")

	nl, err := d.ExtractFromFS(source, &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	require.NotNil(t, nl)

	// 2 packages + 90 base-files entries + 299 libc6 entries (the "/." root
	// entry of each .list file is skipped).
	require.Len(t, nl.GetNodes(), 391)

	// Spot-check the libc6 shared object got its digest from the multi-arch
	// qualified md5sums file.
	var so *sbom.Node
	for _, n := range nl.GetNodes() {
		if n.GetName() == "/usr/lib/x86_64-linux-gnu/libc.so.6" {
			so = n
			break
		}
	}
	require.NotNil(t, so, "libc.so.6 file node missing")
	assert.Equal(t,
		"09f09e790a0a57d2a5ea23d02d1f26e1",
		so.GetHashes()[int32(sbom.HashAlgorithm_MD5)],
	)
}

// TestExtractFromFS_Distroless runs against testdata/distroless-static: the
// verbatim var/lib/dpkg/status.d and os-release of a
// gcr.io/distroless/static-debian12 image. Stanzas there carry no Status
// field and the os-release identifies as debian 12.
func TestExtractFromFS_Distroless(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS("testdata/distroless-static")

	nl, err := d.ExtractFromFS(source, nil)
	require.NoError(t, err)
	require.NotNil(t, nl)

	nodes := nl.GetNodes()
	require.Len(t, nodes, 4)

	byName := map[string]string{}
	for _, n := range nodes {
		byName[n.GetName()] = n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	}
	assert.Equal(t,
		"pkg:deb/debian/base-files@12.4+deb12u14?arch=amd64&distro=debian-12",
		byName["base-files"],
	)
	assert.Equal(t,
		"pkg:deb/debian/tzdata@2026b-0+deb12u1?arch=all&distro=debian-12",
		byName["tzdata"],
	)
	assert.Contains(t, byName, "netbase")
	assert.Contains(t, byName, "media-types")
}

// TestExtractFromFS_DistrolessIncludeFiles checks the distroless file lists
// reconstruct from the status.d md5sums companions: every file node carries
// a digest and an absolute path.
func TestExtractFromFS_DistrolessIncludeFiles(t *testing.T) {
	t.Parallel()
	d := New()
	source := os.DirFS("testdata/distroless-static")

	nl, err := d.ExtractFromFS(source, &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	require.NotNil(t, nl)

	// 4 packages + 938 md5sums entries across the four packages.
	require.Len(t, nl.GetNodes(), 942)

	for _, n := range nl.GetNodes() {
		if n.GetType() != sbom.Node_FILE {
			continue
		}
		assert.NotEmpty(t, n.GetHashes()[int32(sbom.HashAlgorithm_MD5)], n.GetName())
		assert.Equal(t, byte('/'), n.GetName()[0], n.GetName())
	}
}

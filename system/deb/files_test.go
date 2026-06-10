// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestParseMD5Sums(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`d8f8e9b2e7c4f6a1b3c5d7e9f1a3b5c7  usr/bin/curl
0123456789abcdef0123456789abcdef  usr/share/doc/curl/with spaces.txt

malformed line without separator
`)
	sums, err := parseMD5Sums(in)
	require.NoError(t, err)
	assert.Len(t, sums, 2)
	assert.Equal(t, "d8f8e9b2e7c4f6a1b3c5d7e9f1a3b5c7", sums["usr/bin/curl"])
	assert.Equal(t, "0123456789abcdef0123456789abcdef", sums["usr/share/doc/curl/with spaces.txt"])
}

// classicFilesFS builds a classic dpkg layout with one multi-arch package
// (arch-qualified info files) whose list mixes directories (no digest) and
// regular files (digest in md5sums).
func classicFilesFS() fstest.MapFS {
	return fstest.MapFS{
		"var/lib/dpkg/status": &fstest.MapFile{
			Data: []byte(libcStanza),
		},
		"var/lib/dpkg/info/libc6:amd64.list": &fstest.MapFile{
			Data: []byte(`/.
/lib
/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu/libc-2.31.so
/usr/share/doc/libc6/copyright
`),
		},
		"var/lib/dpkg/info/libc6:amd64.md5sums": &fstest.MapFile{
			Data: []byte(`aabbccddeeff00112233445566778899  lib/x86_64-linux-gnu/libc-2.31.so
99887766554433221100ffeeddccbbaa  usr/share/doc/libc6/copyright
`),
		},
		"etc/os-release": &fstest.MapFile{Data: []byte(debianOSRelease)},
	}
}

func TestExtractFromFS_IncludeFilesClassic(t *testing.T) {
	t.Parallel()
	d := New()
	nl, err := d.ExtractFromFS(classicFilesFS(), &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	require.NotNil(t, nl)

	// 1 package + 4 files ("/." is skipped)
	nodes := nl.GetNodes()
	require.Len(t, nodes, 5)

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

	// Directories appear without hashes, regular files with their MD5.
	dir := byName["/lib"]
	require.NotNil(t, dir)
	assert.Empty(t, dir.GetHashes())

	so := byName["/lib/x86_64-linux-gnu/libc-2.31.so"]
	require.NotNil(t, so)
	assert.Equal(t,
		"aabbccddeeff00112233445566778899",
		so.GetHashes()[int32(sbom.HashAlgorithm_MD5)],
	)

	// All files hang off the package via "contains" edges.
	for _, edge := range nl.GetEdges() {
		assert.Equal(t, pkgNode.GetId(), edge.GetFrom())
		assert.Equal(t, sbom.Edge_contains, edge.GetType())
		assert.Len(t, edge.GetTo(), 4)
	}
}

func TestExtractFromFS_IncludeFilesOff(t *testing.T) {
	t.Parallel()
	d := New()
	nl, err := d.ExtractFromFS(classicFilesFS(), nil)
	require.NoError(t, err)
	require.NotNil(t, nl)
	assert.Len(t, nl.GetNodes(), 1, "file nodes need IncludeFiles")
}

func TestExtractFromFS_IncludeFilesDistroless(t *testing.T) {
	t.Parallel()
	source := fstest.MapFS{
		"var/lib/dpkg/status.d/base-files": &fstest.MapFile{
			Data: []byte(`Package: base-files
Version: 11.1+deb11u7
Architecture: amd64
Description: Debian base system miscellaneous files
`),
		},
		"var/lib/dpkg/status.d/base-files.md5sums": &fstest.MapFile{
			Data: []byte(`bbc8c6a09a87423a4a4cb43c1c9a9d49  etc/debian_version
89408008f2585c957c031716600d5a80  etc/host.conf
`),
		},
		// A package with no md5sums companion: contributes no file nodes.
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
	nl, err := d.ExtractFromFS(source, &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	require.NotNil(t, nl)

	// 2 packages + 2 files
	nodes := nl.GetNodes()
	require.Len(t, nodes, 4)

	var files []*sbom.Node
	for _, n := range nodes {
		if n.GetType() == sbom.Node_FILE {
			files = append(files, n)
		}
	}
	require.Len(t, files, 2)
	for _, f := range files {
		// md5sums paths get normalized to absolute, like .list paths.
		assert.True(t, strings.HasPrefix(f.GetName(), "/etc/"), f.GetName())
		assert.NotEmpty(t, f.GetHashes()[int32(sbom.HashAlgorithm_MD5)])
	}
}

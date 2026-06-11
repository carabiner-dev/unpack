// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package apk

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInstalled(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`C:Q1D35YJ+ThpzYxvtont4QxqLokDgU=
P:musl
V:1.2.6-r2
A:x86_64
S:415475
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1775900007
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q1HDbpApgJLhKPJN6IjaA7wJ3Oa4o=
R:libc.musl-x86_64.so.1
a:0:0:777
Z:Q17yJ3JFNypA4mxhJJr0ou6CzsJVI=

C:Q1deadbeefdeadbeefdeadbeefdead=
P:busybox-binsh
V:1.37.0-r30
A:x86_64
L:GPL-2.0-only
o:busybox
`)
	pkgs, err := parseInstalled(in)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)

	musl := pkgs[0]
	assert.Equal(t, "musl", musl.Name)
	assert.Equal(t, "1.2.6-r2", musl.Version)
	assert.Equal(t, "x86_64", musl.Arch)
	assert.Equal(t, "the musl c library (libc) implementation", musl.Description)
	assert.Equal(t, "https://musl.libc.org/", musl.URL)
	assert.Equal(t, "MIT", musl.License)
	assert.Equal(t, "musl", musl.Origin)
	assert.Equal(t, "Natanael Copa", musl.Maintainer)
	assert.Equal(t, "ncopa@alpinelinux.org", musl.Email)
	assert.Equal(t, "0f7e5827e4e1a73631beda27b78431a8ba240e05", musl.Checksum)

	// Two R: files with Z: digests; the F: directory record only provides
	// the path prefix and the a: permission lines between R: and Z: don't
	// break the association.
	require.Len(t, musl.Files, 2)
	assert.Equal(t, "/lib/ld-musl-x86_64.so.1", musl.Files[0].Path)
	assert.Equal(t, "1c36e90298092e128f24de888da03bc09dce6b8a", musl.Files[0].SHA1)
	assert.Equal(t, "/lib/libc.musl-x86_64.so.1", musl.Files[1].Path)
	assert.Equal(t, "ef2277245372a40e26c61249af4a2ee82cec2552", musl.Files[1].SHA1)

	// Subpackages keep their origin for the upstream qualifier.
	assert.Equal(t, "busybox", pkgs[1].Origin)
	assert.Empty(t, pkgs[1].Files)
}

func TestDecodeChecksum(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		"1c36e90298092e128f24de888da03bc09dce6b8a",
		decodeChecksum("Q1HDbpApgJLhKPJN6IjaA7wJ3Oa4o="),
	)
	// Unknown encodings and garbage are dropped, not mislabeled.
	assert.Empty(t, decodeChecksum("Q2something"))
	assert.Empty(t, decodeChecksum("Q1***notbase64***"))
	assert.Empty(t, decodeChecksum(""))
}

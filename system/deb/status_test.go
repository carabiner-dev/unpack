// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStatus(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 12837
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.31-13+deb11u6
Depends: libgcc-s1, libcrypt1 (>= 1:4.1.0)
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system. This package includes shared versions of the standard C library.
Homepage: https://www.gnu.org/software/libc/libc.html

Package: tzdata
Status: deinstall ok config-files
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: all
Version: 2021a-1+deb11u10
Description: time zone and daylight-saving time data

Package: base-files
Status: install ok installed
Maintainer: Santiago Vila <sanvila@debian.org>
Architecture: amd64
Version: 11.1+deb11u7
Source: base-files (11.1+deb11u6)
Description: Debian base system miscellaneous files
 This package contains the basic filesystem hierarchy.
Conffiles:
 /etc/debian_version bbc8c6a09a87423a4a4cb43c1c9a9d49
 /etc/host.conf 89408008f2585c957c031716600d5a80
`)
	pkgs, err := parseStatus(in)
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	libc := pkgs[0]
	assert.Equal(t, "libc6", libc.Name)
	assert.Equal(t, "2.31-13+deb11u6", libc.Version)
	assert.Equal(t, "amd64", libc.Architecture)
	assert.Equal(t, "glibc", libc.Source)
	assert.Empty(t, libc.SourceVersion)
	assert.Equal(t, "GNU Libc Maintainers", libc.Maintainer)
	assert.Equal(t, "debian-glibc@lists.debian.org", libc.Email)
	assert.Equal(t, "https://www.gnu.org/software/libc/libc.html", libc.Homepage)
	assert.Equal(t, "GNU C Library: Shared libraries", libc.Summary)
	assert.True(t, libc.Installed())

	// Removed-but-not-purged stanza is parsed but reports not installed.
	assert.Equal(t, "tzdata", pkgs[1].Name)
	assert.False(t, pkgs[1].Installed())

	// Source version in parentheses is split out; Conffiles continuation
	// lines don't leak into the fields.
	base := pkgs[2]
	assert.Equal(t, "base-files", base.Source)
	assert.Equal(t, "11.1+deb11u6", base.SourceVersion)
	assert.True(t, base.Installed())
}

func TestParseStatusSingleStanzaNoStatus(t *testing.T) {
	t.Parallel()
	// A distroless status.d entry: one stanza, no Status field, and no
	// trailing blank line.
	in := strings.NewReader(`Package: base-files
Version: 11.1+deb11u7
Architecture: amd64
Maintainer: Santiago Vila <sanvila@debian.org>
Description: Debian base system miscellaneous files`)
	pkgs, err := parseStatus(in)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "base-files", pkgs[0].Name)
	assert.True(t, pkgs[0].Installed())
}

func TestSplitSource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, name, version string
	}{
		{"glibc", "glibc", ""},
		{"glibc (2.31-13+deb11u6)", "glibc", "2.31-13+deb11u6"},
		{"base-files (11.1+deb11u6)", "base-files", "11.1+deb11u6"},
	} {
		name, version := splitSource(tc.in)
		assert.Equal(t, tc.name, name, tc.in)
		assert.Equal(t, tc.version, version, tc.in)
	}
}

func TestSplitMaintainer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, name, email string
	}{
		{"Santiago Vila <sanvila@debian.org>", "Santiago Vila", "sanvila@debian.org"},
		{"Just A Name", "Just A Name", ""},
	} {
		name, email := splitMaintainer(tc.in)
		assert.Equal(t, tc.name, name, tc.in)
		assert.Equal(t, tc.email, email, tc.in)
	}
}

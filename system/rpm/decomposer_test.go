// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rpm

import (
	"strings"
	"testing"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/stretchr/testify/assert"
)

func intPtr(v int) *int { return &v }

func TestRpmPurl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pkg  rpmdb.PackageInfo
		osr  osRelease
		want string
	}{
		{
			name: "spec example: curl on fedora 25",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1.fc25", Arch: "i386",
			},
			osr:  osRelease{ID: "fedora", VersionID: "25"},
			want: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
		},
		{
			name: "epoch becomes a qualifier",
			pkg: rpmdb.PackageInfo{
				Name: "centerim", Version: "4.22.10", Release: "1.el6",
				Arch: "i686", Epoch: intPtr(1),
			},
			osr:  osRelease{ID: "fedora", VersionID: "25"},
			want: "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&distro=fedora-25&epoch=1",
		},
		{
			name: "epoch zero is omitted",
			pkg: rpmdb.PackageInfo{
				Name: "bash", Version: "5.2.15", Release: "1.fc38",
				Arch: "x86_64", Epoch: intPtr(0),
			},
			osr:  osRelease{ID: "fedora", VersionID: "38"},
			want: "pkg:rpm/fedora/bash@5.2.15-1.fc38?arch=x86_64&distro=fedora-38",
		},
		{
			name: "upstream qualifier from source rpm",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1.fc26", Arch: "x86_64",
				SourceRpm: "curl-7.50.3-1.fc26.src.rpm",
			},
			osr:  osRelease{ID: "fedora", VersionID: "26"},
			want: "pkg:rpm/fedora/curl@7.50.3-1.fc26?arch=x86_64&distro=fedora-26&upstream=curl-7.50.3-1.fc26.src.rpm",
		},
		{
			name: "namespace lowercased",
			pkg: rpmdb.PackageInfo{
				Name: "openssl", Version: "3.0.7", Release: "18.el9_2",
				Arch: "x86_64",
			},
			osr:  osRelease{ID: "RHEL", VersionID: "9.2"},
			want: "pkg:rpm/rhel/openssl@3.0.7-18.el9_2?arch=x86_64&distro=rhel-9.2",
		},
		{
			name: "arch lowercased",
			pkg: rpmdb.PackageInfo{
				Name: "kernel", Version: "6.4.6", Release: "200.fc38", Arch: "X86_64",
			},
			osr:  osRelease{ID: "fedora", VersionID: "38"},
			want: "pkg:rpm/fedora/kernel@6.4.6-200.fc38?arch=x86_64&distro=fedora-38",
		},
		{
			name: "modularitylabel encoded",
			pkg: rpmdb.PackageInfo{
				Name: "nodejs", Version: "14.21.3", Release: "1.module_f38+18119+78d34c93",
				Arch:            "x86_64",
				Modularitylabel: "nodejs:14:8060020220421152133:e6e4d6a4",
			},
			osr:  osRelease{ID: "fedora", VersionID: "38"},
			want: "pkg:rpm/fedora/nodejs@14.21.3-1.module_f38+18119+78d34c93?arch=x86_64&distro=fedora-38&modularitylabel=nodejs%3A14%3A8060020220421152133%3Ae6e4d6a4",
		},
		{
			name: "no os-release info: namespace and distro omitted",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1", Arch: "x86_64",
			},
			osr:  osRelease{},
			want: "pkg:rpm/curl@7.50.3-1?arch=x86_64",
		},
		{
			name: "qualifiers sorted alphabetically",
			pkg: rpmdb.PackageInfo{
				Name: "curl", Version: "7.50.3", Release: "1.fc26", Arch: "x86_64",
				Epoch: intPtr(2), SourceRpm: "curl-7.50.3-1.fc26.src.rpm",
			},
			osr:  osRelease{ID: "fedora", VersionID: "26"},
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

func TestParseOSRelease(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`NAME="Fedora Linux"
VERSION="38 (Workstation Edition)"
ID=fedora
ID_LIKE=fedora
VERSION_ID=38
# a comment
PRETTY_NAME="Fedora Linux 38 (Workstation Edition)"
`)
	got, err := parseOSRelease(in)
	assert.NoError(t, err)
	assert.Equal(t, "fedora", got.ID)
	assert.Equal(t, "38", got.VersionID)
	assert.Equal(t, "fedora", got.Namespace())
	assert.Equal(t, "fedora-38", got.Distro())
}

func TestOSReleaseDistroEmpty(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", osRelease{}.Distro())
	assert.Equal(t, "", osRelease{ID: "fedora"}.Distro())
	assert.Equal(t, "", osRelease{VersionID: "38"}.Distro())
}

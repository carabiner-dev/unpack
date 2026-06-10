// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osrelease

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`NAME="Fedora Linux"
VERSION="38 (Workstation Edition)"
ID=fedora
ID_LIKE=fedora
VERSION_ID=38
# a comment
PRETTY_NAME="Fedora Linux 38 (Workstation Edition)"
`)
	got, err := Parse(in)
	require.NoError(t, err)
	assert.Equal(t, "fedora", got.ID)
	assert.Equal(t, "38", got.VersionID)
	assert.Equal(t, "fedora", got.Namespace())
	assert.Equal(t, "fedora-38", got.Distro())
}

func TestDistroEmpty(t *testing.T) {
	t.Parallel()
	assert.Empty(t, Data{}.Distro())
	assert.Empty(t, Data{ID: "fedora"}.Distro())
	assert.Empty(t, Data{VersionID: "38"}.Distro())
}

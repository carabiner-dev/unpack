// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// The fixtures are the source package's; this package only finds them on a
// filesystem and hands them over.
const fixture = "../../source/composer/testdata/installed"

func TestExtractFromFS(t *testing.T) {
	t.Parallel()

	nl, err := New().ExtractFromFS(os.DirFS(fixture), &api.DecomposerOptions{})
	require.NoError(t, err)
	require.NotNil(t, nl)
	require.NotEmpty(t, nl.GetNodes())
	require.Len(t, nl.GetRootElements(), 2)
}

// TestExtractFromFSNoComposer pins the contract shared with the other
// system decomposers: a filesystem with no Composer on it reads as
// (nil, nil), so its absence never breaks an image scan.
func TestExtractFromFSNoComposer(t *testing.T) {
	t.Parallel()

	nl, err := New().ExtractFromFS(os.DirFS(t.TempDir()), &api.DecomposerOptions{})
	require.NoError(t, err)
	require.Nil(t, nl)
}

func TestExtract(t *testing.T) {
	t.Parallel()

	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: fixture})
	require.NoError(t, err)
	require.NotEmpty(t, nl.GetNodes())

	_, err = New().Extract(&api.DecomposerOptions{})
	require.Error(t, err)
}

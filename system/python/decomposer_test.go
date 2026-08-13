// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"os"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// The fixture is the source package's real installed environment; this
// package only has to find it on a filesystem and hand it over.
const fixture = "../../source/python/testdata/sitepackages"

func TestExtractFromFS(t *testing.T) {
	t.Parallel()

	nl, err := New().ExtractFromFS(os.DirFS(fixture), &api.DecomposerOptions{})
	require.NoError(t, err)
	require.NotNil(t, nl)
	require.Len(t, nl.GetNodes(), 7)
	require.NotEmpty(t, nl.GetRootElements())
	require.NotEmpty(t, nl.GetEdges())
}

// TestExtractFromFSNoPython pins the contract shared with the other system
// decomposers: a filesystem with no Python on it reads as (nil, nil), so
// its absence never breaks an image scan.
func TestExtractFromFSNoPython(t *testing.T) {
	t.Parallel()

	nl, err := New().ExtractFromFS(os.DirFS(t.TempDir()), &api.DecomposerOptions{})
	require.NoError(t, err)
	require.Nil(t, nl)
}

func TestExtract(t *testing.T) {
	t.Parallel()

	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: fixture})
	require.NoError(t, err)
	require.Len(t, nl.GetNodes(), 7)

	_, err = New().Extract(&api.DecomposerOptions{})
	require.Error(t, err)
}

func TestExtractFromFSIncludeFiles(t *testing.T) {
	t.Parallel()

	nl, err := New().ExtractFromFS(os.DirFS(fixture), &api.DecomposerOptions{IncludeFiles: true})
	require.NoError(t, err)
	files := 0
	for _, n := range nl.GetNodes() {
		if n.GetType() == sbom.Node_FILE {
			files++
		}
	}
	require.NotZero(t, files)
}

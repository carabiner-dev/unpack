// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// catalogedFiles lists what an index holds, as paths relative to root,
// slash-separated and sorted.
func catalogedFiles(t *testing.T, root string, index *PathIndex) []string {
	t.Helper()
	files := []string{}
	for dir, names := range *index {
		for _, name := range names {
			rel, err := filepath.Rel(root, filepath.Join(dir, name))
			require.NoError(t, err)
			files = append(files, filepath.ToSlash(rel))
		}
	}
	sort.Strings(files)
	return files
}

// TestCatalogDirectoriesIgnoresFromRoot checks that ignore patterns are
// matched against what is under the directory being cataloged and not
// against the directories leading to it: a tree that itself sits under a
// directory a pattern names is cataloged like any other, and the pattern
// still hides what it names inside the tree.
func TestCatalogDirectoriesIgnoresFromRoot(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// parent is where the cataloged tree sits, under a temp dir.
		parent string
		opts   []optFn
	}{
		{name: "under a plain directory", parent: "src"},
		{name: "under a directory a default pattern names", parent: "node_modules"},
		{name: "under nested ones", parent: "vendor/node_modules/.venv"},
		{
			name:   "under a directory an extra pattern names",
			parent: "build",
			opts:   []optFn{WithExtraIgnorePattners([]string{"build/"})},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			root := filepath.Join(t.TempDir(), filepath.FromSlash(tc.parent), "app")
			for _, file := range []string{
				"go.mod",
				"cmd/main.go",
				"node_modules/dep/package.json",
				"build/out.bin",
			} {
				path := filepath.Join(root, filepath.FromSlash(file))
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
			}

			want := []string{"build/out.bin", "cmd/main.go", "go.mod"}
			if len(tc.opts) > 0 {
				want = []string{"cmd/main.go", "go.mod"}
			}

			// By its absolute path, which holds the parent directories.
			index, err := (&Indexer{}).CatalogDirectories(root, tc.opts...)
			require.NoError(t, err)
			require.Equal(t, want, catalogedFiles(t, root, index))

			locations, err := index.FindFileLocations("go.mod")
			require.NoError(t, err)
			require.Equal(t, []string{root}, locations)
		})
	}
}

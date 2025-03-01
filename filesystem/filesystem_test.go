// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"os"
	"sort"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestReadtTree(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		expect  []string
		mustErr bool
	}{
		{"normal", "testdata/fs", []string{".gitignore", "LICENSE", "img/cats.gif", "test.html"}, false},
		{"err", "testdata/nonexistent", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Decomposer{}
			res, err := d.readtTree(os.DirFS(tc.path))
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			sort.Strings(res)
			require.Equal(t, tc.expect, res)
		})
	}
}

func TestProcessFile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		path    string
		hash    string
		mustErr bool
	}{
		{"normal", "LICENSE", "9a2dd24a9033abc18c57b8528ab3026e1df6b5fde158512bbbdacff90155d188", false},
		{"notfound", "not-existing.txt", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, err := New()
			require.NoError(t, err)
			d.Hasher.Options.Algorithms = []intoto.HashAlgorithm{intoto.AlgorithmSHA256}

			n, err := d.processFile(os.DirFS("testdata/fs"), tc.path)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tc.path, n.FileName)
			require.Len(t, n.Hashes, 1)
			require.Equal(t, n.Hashes[3], tc.hash)
		})
	}
}

func TestIgnorePatterns(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		morepatterns     []string
		noGitIgnore      bool
		mustErr          bool
		expectedPatterns int
	}{
		{"normal", nil, false, false, 3},
		{"nogitignore-patterns", []string{"go.work", "go.work.sum"}, true, false, 2},
		{"nogitignore-no-patterns", nil, true, false, 0},
		{"patterns", []string{"go.work", "go.work.sum"}, false, false, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, err := New()
			require.NoError(t, err)

			d.Options.IgnorePatterns = tc.morepatterns
			d.Options.NoGitignore = tc.noGitIgnore

			patterns, err := d.ignorePatterns(os.DirFS("testdata/fs"), ".")
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, patterns, tc.expectedPatterns)
		})
	}
}

func TestIndexFS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		path        string
		expectedLen int
		ignore      []string
		mustErr     bool
	}{
		{"normal", "testdata/fs", 3, nil, false},
		{"notfound", "testdata/nonexistent", 0, nil, true},
		{"normal", "testdata/fs", 2, []string{"LICENSE"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, err := New()
			require.NoError(t, err)

			if tc.ignore != nil {
				d.Options.IgnorePatterns = tc.ignore
			}

			nl, err := d.IndexFS(os.DirFS(tc.path))
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, nl.Nodes, tc.expectedLen)
		})
	}
}

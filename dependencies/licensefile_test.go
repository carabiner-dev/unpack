// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// licenseText returns the text of a license the classifier knows: this
// repository's own.
func licenseText(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../LICENSE.txt")
	require.NoError(t, err)
	return data
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestFindLicenseFile(t *testing.T) {
	t.Parallel()
	text := licenseText(t)

	t.Run("in the codebase", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "LICENSE"), text)
		id, path := findLicenseFile(dir)
		require.Equal(t, "Apache-2.0", id)
		require.Equal(t, "LICENSE", filepath.Base(path))
	})

	t.Run("at the root of the repository", func(t *testing.T) {
		t.Parallel()
		repo := t.TempDir()
		write(t, filepath.Join(repo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))
		write(t, filepath.Join(repo, "COPYING"), text)
		sub := filepath.Join(repo, "services", "api")
		require.NoError(t, os.MkdirAll(sub, 0o750))

		id, path := findLicenseFile(sub)
		require.Equal(t, "Apache-2.0", id)
		require.Equal(t, filepath.Join(repo, "COPYING"), path)
	})

	t.Run("not above the repository", func(t *testing.T) {
		t.Parallel()
		outside := t.TempDir()
		write(t, filepath.Join(outside, "LICENSE"), text)
		repo := filepath.Join(outside, "repo")
		write(t, filepath.Join(repo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))

		id, _ := findLicenseFile(repo)
		require.Empty(t, id)
	})

	t.Run("not above a directory in no repository", func(t *testing.T) {
		t.Parallel()
		outside := t.TempDir()
		write(t, filepath.Join(outside, "LICENSE"), text)
		sub := filepath.Join(outside, "project")
		require.NoError(t, os.MkdirAll(sub, 0o750))

		// The temporary directory may itself be inside a repository on
		// some machine; only then is the search allowed to go up.
		if repositoryRoot(sub) != "" {
			t.Skip("the temporary directory is inside a git repository")
		}
		id, _ := findLicenseFile(sub)
		require.Empty(t, id)
	})
}

// licensedDecomposer returns one root, with the license it is given.
type licensedDecomposer struct{ license string }

func (l *licensedDecomposer) Extract(*api.DecomposerOptions) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	root := &sbom.Node{Id: "root", Name: "root"}
	if l.license != "" {
		root.Licenses = []string{l.license}
	}
	nl.AddRootNode(root)
	return nl, nil
}
func (l *licensedDecomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }
func (l *licensedDecomposer) DefaultOptions() any                                   { return nil }

// TestExtractReadsLicenseFile checks a root the decomposer found no
// license for takes the license file's, that a license the decomposer
// found stands, and that the option turns the reading off.
func TestExtractReadsLicenseFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "LICENSE"), licenseText(t))

	extract := func(d api.Decomposer, read bool) []string {
		opts := DefaultOptions
		opts.ReadGitVersion = false
		opts.ReadLicenseFile = read
		impl := &defaultImplementation{}
		extractions, err := impl.ExtractCodeBases(t.Context(), &opts, map[api.Decomposer][]string{d: {dir}})
		require.NoError(t, err)
		require.Len(t, extractions, 1)
		return extractions[0].NodeList.GetRootNodes()[0].GetLicenses()
	}

	require.Equal(t, []string{"Apache-2.0"}, extract(&licensedDecomposer{}, true))
	require.Equal(t, []string{"MIT"}, extract(&licensedDecomposer{license: "MIT"}, true))
	require.Empty(t, extract(&licensedDecomposer{}, false))
}

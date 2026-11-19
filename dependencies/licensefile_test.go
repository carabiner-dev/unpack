// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog"
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

// TestMultipleCodebasesWarning checks that taking the first of several
// codebases is said to the caller's logger, and to nobody when the caller
// wired none: the unpacker has no logger of its own.
func TestMultipleCodebasesWarning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "composer.lock"), []byte(`{"packages": []}`))
	write(t, filepath.Join(dir, "composer.json"), []byte(`{"name": "example/app"}`))
	write(t, filepath.Join(dir, "Gemfile.lock"), []byte("GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n"))

	unpacker := NewUnpacker()
	unpacker.Options.FailOnSingleMulti = false
	unpacker.Options.ReadGitVersion = false
	unpacker.Options.Networking = api.NetworkDisabled

	var out bytes.Buffer
	ctx := clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&out, nil)))
	extraction, err := unpacker.CodebaseExtraction(ctx, dir)
	require.NoError(t, err)
	require.NotNil(t, extraction)
	require.Contains(t, out.String(), "level=WARN")
	require.Contains(t, out.String(), "2 codebases found, only returning the first")

	// With FailOnSingleMulti, the default, it is an error and no log.
	out.Reset()
	unpacker.Options.FailOnSingleMulti = true
	_, err = unpacker.CodebaseExtraction(ctx, dir)
	require.ErrorIs(t, err, ErrMultipleCodebases)
	require.Empty(t, out.String())
}

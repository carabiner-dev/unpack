// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/composer"
)

// A codebase is detected even when the file that marks it is gitignored.
// Composer libraries routinely ignore composer.lock; the project is still
// a PHP codebase. .gitignore only governs cataloging files into the SBOM.
func TestScanPathsFindsGitignoredLockfile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"composer.json": `{"name": "acme/lib"}`,
		"composer.lock": `{"packages": []}`,
		".gitignore":    "/vendor/\ncomposer.lock\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	// A directory git would skip but that holds no codebase marker either
	// way; it must not break the walk.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o750))

	opts := DefaultOptions
	impl := &defaultImplementation{}
	indices, err := impl.IndexPaths(context.Background(), &opts, Sources{Paths: []string{dir}})
	require.NoError(t, err)

	php := composer.New()
	found, err := impl.ScanPaths(context.Background(), &opts, map[string]api.Decomposer{"php": php}, indices)
	require.NoError(t, err)
	require.Equal(t, []string{dir}, found[php])
}

// Install trees are skipped without any pattern from the caller: vendored
// Composer packages ship their own composer.lock.
func TestScanPathsSkipsInstallTrees(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sub := filepath.Join(dir, "vendor", "acme", "dep")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "composer.lock"), []byte(`{"packages": []}`), 0o600))

	opts := DefaultOptions
	impl := &defaultImplementation{}
	indices, err := impl.IndexPaths(context.Background(), &opts, Sources{Paths: []string{dir}})
	require.NoError(t, err)

	php := composer.New()
	found, err := impl.ScanPaths(context.Background(), &opts, map[string]api.Decomposer{"php": php}, indices)
	require.NoError(t, err)
	require.Empty(t, found[php])
}

// Caller-supplied ignore patterns still apply to detection.
func TestScanPathsHonorsIgnorePatterns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sub := filepath.Join(dir, "third_party", "acme", "dep")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "composer.lock"), []byte(`{"packages": []}`), 0o600))

	opts := DefaultOptions
	opts.IgnorePatterns = []string{"third_party/"}
	impl := &defaultImplementation{}
	indices, err := impl.IndexPaths(context.Background(), &opts, Sources{Paths: []string{dir}})
	require.NoError(t, err)

	php := composer.New()
	found, err := impl.ScanPaths(context.Background(), &opts, map[string]api.Decomposer{"php": php}, indices)
	require.NoError(t, err)
	require.Empty(t, found[php])
}

// TestExtractionsCarryTheDecomposersContext checks a codebase comes back
// with the context its decomposer reads in, and that the plain methods
// return the same node lists as before.
func TestExtractionsCarryTheDecomposersContext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"composer.json": `{"name": "acme/app"}`,
		"composer.lock": `{"packages": []}`,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}

	unpacker := NewUnpacker()
	unpacker.Options.Networking = api.NetworkDisabled
	unpacker.Options.ReadGitVersion = false

	extractions, err := unpacker.Extractions(context.Background(), &Codebase{Path: dir})
	require.NoError(t, err)
	require.Len(t, extractions, 1)
	require.Equal(t, []api.GenerationContext{api.ContextSource}, extractions[0].Contexts)

	lists, err := unpacker.Extract(context.Background(), &Codebase{Path: dir})
	require.NoError(t, err)
	require.Len(t, lists, 1)
	require.Len(t, lists[0].GetNodes(), len(extractions[0].NodeList.GetNodes()))

	one, err := unpacker.CodebaseExtraction(context.Background(), dir)
	require.NoError(t, err)
	require.NotNil(t, one)
	require.Equal(t, []api.GenerationContext{api.ContextSource}, one.Contexts)

	// A directory holding no codebase is no extraction, and no error.
	none, err := unpacker.CodebaseExtraction(context.Background(), t.TempDir())
	require.NoError(t, err)
	require.Nil(t, none)
	nl, err := unpacker.ExtractCodebaseWithContext(context.Background(), t.TempDir())
	require.NoError(t, err)
	require.Nil(t, nl)
}

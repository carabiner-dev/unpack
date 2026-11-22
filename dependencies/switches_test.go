// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

// markerDecomposer finds a codebase wherever a file of its name is.
type markerDecomposer struct{ marker string }

func (m *markerDecomposer) Extract(*api.DecomposerOptions) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	nl.AddRootNode(&sbom.Node{Id: m.marker, Name: m.marker})
	return nl, nil
}
func (m *markerDecomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }
func (m *markerDecomposer) DefaultOptions() any                                   { return nil }
func (m *markerDecomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations(m.marker)
}

// switchUnpacker returns an unpacker that runs "plain" by default and
// knows "approx", which runs only when switched on, with a directory
// holding a codebase of each.
func switchUnpacker(t *testing.T) (unpacker *Unpacker, dir string) {
	t.Helper()
	dir = t.TempDir()
	write(t, filepath.Join(dir, "plain.lock"), []byte("x"))
	write(t, filepath.Join(dir, "approx.txt"), []byte("x"))

	unpacker = NewUnpacker()
	unpacker.decomposers = map[string]api.Decomposer{"plain": &markerDecomposer{marker: "plain.lock"}}
	unpacker.available = map[string]func() api.Decomposer{
		"approx": func() api.Decomposer { return &markerDecomposer{marker: "approx.txt"} },
	}
	unpacker.Options.ReadGitVersion = false
	unpacker.Options.ReadLicenseFile = false
	return unpacker, dir
}

func languages(t *testing.T, unpacker *Unpacker, dir string) []string {
	t.Helper()
	codebases, err := unpacker.ListCodebases(t.Context(), dir)
	require.NoError(t, err)
	found := make([]string, 0, len(codebases))
	for _, cb := range codebases {
		found = append(found, cb.Language)
	}
	return found
}

func TestDecomposerSwitches(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		unpacker, dir := switchUnpacker(t)
		require.Equal(t, []string{"approx", "plain"}, unpacker.DecomposerNames())
		require.Equal(t, []string{"plain"}, unpacker.DefaultDecomposerNames())
		require.Equal(t, []string{"plain"}, languages(t, unpacker, dir))
	})

	t.Run("one switched on", func(t *testing.T) {
		t.Parallel()
		unpacker, dir := switchUnpacker(t)
		unpacker.Options.Decomposers = map[string]bool{"approx": true}
		require.ElementsMatch(t, []string{"approx", "plain"}, languages(t, unpacker, dir))

		// And it extracts: the decomposer scanning found is the one
		// extraction runs.
		unpacker.Options.CodebaseFilter = "approx:."
		lists, err := unpacker.Extract(t.Context(), &Codebase{Path: dir})
		require.NoError(t, err)
		require.Len(t, lists, 1)
		require.Equal(t, "approx.txt", lists[0].GetRootNodes()[0].GetName())
	})

	t.Run("one switched off", func(t *testing.T) {
		t.Parallel()
		unpacker, dir := switchUnpacker(t)
		unpacker.Options.Decomposers = map[string]bool{"plain": false}
		require.Empty(t, languages(t, unpacker, dir))
	})

	t.Run("both", func(t *testing.T) {
		t.Parallel()
		unpacker, dir := switchUnpacker(t)
		unpacker.Options.Decomposers = map[string]bool{"plain": false, "approx": true}
		require.Equal(t, []string{"approx"}, languages(t, unpacker, dir))
	})

	t.Run("switched to what they already are", func(t *testing.T) {
		t.Parallel()
		unpacker, dir := switchUnpacker(t)
		unpacker.Options.Decomposers = map[string]bool{"plain": true, "approx": false}
		require.Equal(t, []string{"plain"}, languages(t, unpacker, dir))
	})

	t.Run("a registered one can be switched off", func(t *testing.T) {
		t.Parallel()
		unpacker, dir := switchUnpacker(t)
		unpacker.RegisterDecomposerAs("extra", &markerDecomposer{marker: "approx.txt"})
		require.ElementsMatch(t, []string{"extra", "plain"}, languages(t, unpacker, dir))
		unpacker.Options.Decomposers = map[string]bool{"extra": false}
		require.Equal(t, []string{"plain"}, languages(t, unpacker, dir))
	})

	t.Run("an unknown name", func(t *testing.T) {
		t.Parallel()
		for _, on := range []bool{true, false} {
			unpacker, dir := switchUnpacker(t)
			unpacker.Options.Decomposers = map[string]bool{"aprox": on}
			_, err := unpacker.ListCodebases(t.Context(), dir)
			require.ErrorIs(t, err, ErrUnknownDecomposer)
			require.ErrorContains(t, err, "aprox")
			require.ErrorContains(t, err, "approx, plain")

			_, err = unpacker.Extract(t.Context(), &Codebase{Path: dir})
			require.ErrorIs(t, err, ErrUnknownDecomposer)
		}
	})
}

// The built-in set: the languages read from a lock or a manifest run by
// default, and CMake, whose reading is an approximation, only when asked
// for.
func TestDefaultDecomposers(t *testing.T) {
	t.Parallel()
	unpacker := NewUnpacker()
	require.Equal(t,
		[]string{"conan", "golang", "maven", "npm", "nuget", "php", "python", "ruby", "rust", "swift"},
		unpacker.DefaultDecomposerNames(),
	)
	require.Equal(t,
		[]string{"cmake", "conan", "golang", "maven", "npm", "nuget", "php", "pkgconf", "python", "ruby", "rust", "swift"},
		unpacker.DecomposerNames(),
	)
}

// TestCMakeIsOptIn checks a CMake project is no codebase until the
// decomposer is switched on, and is read once it is.
func TestCMakeIsOptIn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "CMakeLists.txt"), []byte("project(demo VERSION 1.0)\nfind_package(ZLIB REQUIRED)\n"))

	unpacker := NewUnpacker()
	unpacker.Options.ReadGitVersion = false
	require.Empty(t, languages(t, unpacker, dir))

	unpacker.Options.Decomposers = map[string]bool{"cmake": true}
	require.Equal(t, []string{"cmake"}, languages(t, unpacker, dir))

	lists, err := unpacker.Extract(t.Context(), &Codebase{Path: dir})
	require.NoError(t, err)
	require.Len(t, lists, 1)
	require.Equal(t, "demo", lists[0].GetRootNodes()[0].GetName())
	require.Len(t, lists[0].GetNodes(), 2)
}

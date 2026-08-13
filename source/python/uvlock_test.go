// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// readTestLock parses one of the checked-in locks, which were written by
// real uv (0.11) against the pyproject.toml files next to them.
func readTestLock(t *testing.T, name string) *Lockfile {
	t.Helper()
	lock, err := ReadLockfile("testdata/" + name + "/uv.lock")
	require.NoError(t, err)
	return lock
}

// packageByName returns the packages holding a name; a forked lock has more
// than one.
func packagesByName(lock *Lockfile, name string) []*Package {
	found := []*Package{}
	for i := range lock.Packages {
		if lock.Packages[i].Name == name {
			found = append(found, &lock.Packages[i])
		}
	}
	return found
}

func TestParseLockfileSimple(t *testing.T) {
	t.Parallel()

	lock := readTestLock(t, "simple")
	require.Equal(t, 1, lock.Version)
	require.Equal(t, ">=3.10", lock.RequiresPython)
	require.Len(t, lock.Packages, 16)

	// The project's own package is the graph's root, and the lock says so
	// with its source.
	roots := packagesByName(lock, "uvdemo")
	require.Len(t, roots, 1)
	root := roots[0]
	require.True(t, root.Source.IsProject())
	require.False(t, packagesByName(lock, "requests")[0].Source.IsProject())

	// Its runtime dependencies, its extras and its dependency groups are
	// three separate things.
	require.Len(t, root.Dependencies, 2)
	require.Contains(t, root.OptionalDependencies, "color")
	require.Contains(t, root.DevDependencies, "dev")
	require.Equal(t, "colorama", root.OptionalDependencies["color"][0].Name)
	require.Equal(t, "pytest", root.DevDependencies["dev"][0].Name)

	// A conditional edge carries its marker: click needs colorama only on
	// Windows.
	click := packagesByName(lock, "click")[0]
	require.Len(t, click.Dependencies, 1)
	require.Equal(t, "colorama", click.Dependencies[0].Name)
	require.Equal(t, "sys_platform == 'win32'", click.Dependencies[0].Marker)

	// Artifacts carry the hashes: an sdist and wheels per package.
	requests := packagesByName(lock, "requests")[0]
	require.NotNil(t, requests.Sdist)
	algorithm, value := requests.Sdist.HashValue()
	require.Equal(t, "sha256", algorithm)
	require.Len(t, value, 64)
	require.NotEmpty(t, requests.Wheels)
	require.NotZero(t, requests.Sdist.Size)
}

// TestParseLockfileForked reads a lock whose resolution forked: numpy
// appears at three versions, one per Python version range, and the edges
// pointing at it say which one they mean.
func TestParseLockfileForked(t *testing.T) {
	t.Parallel()

	lock := readTestLock(t, "forked")

	// The fork structure is recorded at the top,
	require.NotEmpty(t, lock.ResolutionMarkers)
	require.Equal(t, []string{
		"sys_platform == 'linux'", "sys_platform == 'darwin'",
	}, lock.SupportedMarkers)

	// on the packages,
	numpys := packagesByName(lock, "numpy")
	require.Len(t, numpys, 3)
	versions := map[string]bool{}
	for _, numpy := range numpys {
		require.NotEmpty(t, numpy.ResolutionMarkers,
			"a forked package claims its share of the environments")
		versions[numpy.Version] = true
	}
	require.Len(t, versions, 3, "each fork resolved its own version")

	// and on the edges: each dependency on numpy states the version and
	// source telling the forks apart, plus the marker it holds under.
	root := packagesByName(lock, "uvdemo2")[0]
	numpyEdges := 0
	for _, dep := range root.Dependencies {
		if dep.Name != "numpy" {
			continue
		}
		numpyEdges++
		require.NotEmpty(t, dep.Version, "a forked edge names its target's version")
		require.NotEmpty(t, dep.Source.Registry)
		require.NotEmpty(t, dep.Marker)
		require.True(t, versions[dep.Version], "the edge points at a fork that exists")
	}
	require.Equal(t, 3, numpyEdges)
}

// TestParseLockfileExtras reads a lock where the root depends on an extra
// of another package, requests[socks].
func TestParseLockfileExtras(t *testing.T) {
	t.Parallel()

	lock := readTestLock(t, "extras")

	root := packagesByName(lock, "uvdemo3")[0]
	require.Len(t, root.Dependencies, 1)
	require.Equal(t, "requests", root.Dependencies[0].Name)
	require.Equal(t, []string{"socks"}, root.Dependencies[0].Extra)

	// The extra's own dependencies live on the target package, under the
	// extra's name.
	requests := packagesByName(lock, "requests")[0]
	require.Equal(t, "pysocks", requests.OptionalDependencies["socks"][0].Name)
}

func TestParseLockfileRejects(t *testing.T) {
	t.Parallel()

	for name, doc := range map[string]string{
		"a future schema version": "version = 9\nrequires-python = \">=3.10\"\n",
		"a missing version":       "requires-python = \">=3.10\"\n",
		"a nameless package":      "version = 1\n[[package]]\nversion = \"1.0\"\n",
		"not TOML at all":         "{\"version\": 1}",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseLockfile([]byte(doc))
			require.Error(t, err)
		})
	}

	_, err := ReadLockfile("testdata/does-not-exist/uv.lock")
	require.Error(t, err)
}

// TestParseLockfileNormalizesNames covers the promise the parser makes to
// everything downstream: every name in the result is already canonical,
// even from a lock a human edited.
func TestParseLockfileNormalizesNames(t *testing.T) {
	t.Parallel()

	lock, err := ParseLockfile([]byte(`
version = 1
requires-python = ">=3.10"

[[package]]
name = "My_Project"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "Typing.Extensions", extra = ["My_Extra"] }]

[[package]]
name = "typing-extensions"
version = "4.16.0"
source = { registry = "https://pypi.org/simple" }
`))
	require.NoError(t, err)

	require.Equal(t, "my-project", lock.Packages[0].Name)
	require.Equal(t, "typing-extensions", lock.Packages[0].Dependencies[0].Name)
	require.Equal(t, []string{"my-extra"}, lock.Packages[0].Dependencies[0].Extra)
}

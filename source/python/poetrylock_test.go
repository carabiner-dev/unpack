// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// poetryPackagesByName returns the entries holding a name.
func poetryPackagesByName(lock *PoetryLockfile, name string) []*PoetryPackage {
	found := []*PoetryPackage{}
	for i := range lock.Packages {
		if lock.Packages[i].Name == name {
			found = append(found, &lock.Packages[i])
		}
	}
	return found
}

// TestParsePoetryLockfile reads the checked-in lock written by Poetry 2.x
// (lock format 2.1).
func TestParsePoetryLockfile(t *testing.T) {
	t.Parallel()

	lock, err := ReadPoetryLockfile("testdata/poetry/poetry.lock")
	require.NoError(t, err)
	require.Equal(t, "2.1", lock.Metadata.LockVersion)
	require.Equal(t, ">=3.10", lock.Metadata.PythonVersions)

	// There is no entry for the project's own package: that is the
	// manifest's business, and the difference from a uv lock.
	require.Empty(t, poetryPackagesByName(lock, "poetrydemo"))

	// A 2.1 lock stamps every package with its groups.
	for i := range lock.Packages {
		require.NotEmpty(t, lock.Packages[i].Groups, "%s has no groups", lock.Packages[i].Name)
	}

	// A conditional edge carries its marker...
	click := poetryPackagesByName(lock, "click")[0]
	require.Equal(t, []PoetryDependency{
		{Name: "colorama", Marker: `platform_system == "Windows"`},
	}, click.Dependencies)

	// ...and a package serving several groups applies to each under its
	// own condition. Note the extra == marker: Poetry states membership in
	// a root extra this way, which the marker evaluator already speaks.
	colorama := poetryPackagesByName(lock, "colorama")[0]
	require.ElementsMatch(t, []string{"main", "dev"}, colorama.Groups)
	require.Equal(t, `platform_system == "Windows" or extra == "color"`, colorama.Markers["main"])
	require.Equal(t, `sys_platform == "win32"`, colorama.Markers["dev"])

	// Artifacts are filenames plus hashes, wheel names among them, which
	// is what the wheel selection works on.
	requests := poetryPackagesByName(lock, "requests")[0]
	require.NotEmpty(t, requests.Files)
	sawWheel := false
	for _, file := range requests.Files {
		require.Contains(t, file.Hash, "sha256:")
		if len(file.File) > 4 && file.File[len(file.File)-4:] == ".whl" {
			sawWheel = true
		}
	}
	require.True(t, sawWheel)
}

// TestParsePoetryLockfileLegacy reads the lock written by Poetry 1.8 (lock
// format 2.0), which records no group membership at all.
func TestParsePoetryLockfileLegacy(t *testing.T) {
	t.Parallel()

	lock, err := ReadPoetryLockfile("testdata/poetrylegacy/poetry.lock")
	require.NoError(t, err)
	require.Equal(t, "2.0", lock.Metadata.LockVersion)

	for i := range lock.Packages {
		require.Empty(t, lock.Packages[i].Groups,
			"a 2.0 lock records no groups; membership comes from the manifest")
	}

	click := poetryPackagesByName(lock, "click")[0]
	require.Equal(t, []PoetryDependency{
		{Name: "colorama", Marker: `platform_system == "Windows"`},
	}, click.Dependencies)
}

func TestParsePoetryLockfileShapes(t *testing.T) {
	t.Parallel()

	// The dependency table's three shapes, plus names needing
	// normalization, plus a package-level plain marker.
	lock, err := ParsePoetryLockfile([]byte(`
[[package]]
name = "Sample_Package"
version = "1.0.0"
optional = false
python-versions = ">=3.10"
markers = "python_version < \"3.12\""
files = []

[package.dependencies]
plain = "^2.0"
"With_Marker" = {version = "*", markers = "sys_platform == \"win32\"", extras = ["Fast_JSON"]}
multi = [
    {version = "<2", markers = "python_version < \"3.11\""},
    {version = ">=2", markers = "python_version >= \"3.11\""},
]

[metadata]
lock-version = "2.1"
python-versions = ">=3.10"
content-hash = "abc"
`))
	require.NoError(t, err)

	pkg := lock.Packages[0]
	require.Equal(t, "sample-package", pkg.Name)
	require.Equal(t, map[string]string{"": `python_version < "3.12"`}, pkg.Markers)

	// Sorted by name, the multi-constraint fanned out, names normalized.
	require.Equal(t, []PoetryDependency{
		{Name: "multi", Marker: `python_version < "3.11"`},
		{Name: "multi", Marker: `python_version >= "3.11"`},
		{Name: "plain"},
		{Name: "with-marker", Marker: `sys_platform == "win32"`, Extras: []string{"fast-json"}},
	}, pkg.Dependencies)
}

func TestParsePoetryLockfileRejects(t *testing.T) {
	t.Parallel()

	for name, doc := range map[string]string{
		"an unknown schema": "[metadata]\nlock-version = \"3.0\"\n",
		"no schema at all":  "[metadata]\ncontent-hash = \"abc\"\n",
		"a nameless package": `
[[package]]
version = "1.0"
[metadata]
lock-version = "2.1"
`,
		"not TOML": "{\"metadata\": 1}",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePoetryLockfile([]byte(doc))
			require.Error(t, err)
		})
	}
}

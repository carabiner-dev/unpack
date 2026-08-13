// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// This file reads uv.lock files, the lockfile uv writes next to a
// pyproject.toml. A lock carries the resolved dependency graph for every
// environment the project supports at once: packages may appear at several
// versions guarded by resolution markers, and dependency edges carry the
// markers saying where they hold. What to make of that for one concrete
// environment is the tree builder's business; this file is a faithful
// reading of what the lock says.

// lockVersion is the uv.lock schema version this reader understands.
const lockVersion = 1

// Lockfile is a parsed uv.lock.
type Lockfile struct {
	// Version is the lock schema version, and Revision the revision within
	// it. Additions bump the revision; only breaking changes bump the
	// version, which is the one compatibility is judged by.
	Version  int `toml:"version"`
	Revision int `toml:"revision"`

	// RequiresPython is the project's Python requirement, as a PEP 440
	// specifier set such as ">=3.10".
	RequiresPython string `toml:"requires-python"`

	// ResolutionMarkers split the environments the resolution forked over;
	// SupportedMarkers restrict the environments the project supports at
	// all (tool.uv.environments). Both absent mean one universal
	// resolution.
	ResolutionMarkers []string `toml:"resolution-markers"`
	SupportedMarkers  []string `toml:"supported-markers"`

	Packages []Package `toml:"package"`
}

// Package is one locked package. A package appears once per resolved
// version: the same name shows up several times when the resolution forked
// over environments, each entry claimed by its resolution markers.
type Package struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  Source `toml:"source"`

	// Dependencies are the package's resolved runtime dependencies.
	// OptionalDependencies holds those of each extra, keyed by extra name,
	// and DevDependencies those of each dependency group (PEP 735), keyed
	// by group name.
	Dependencies         []Dependency            `toml:"dependencies"`
	OptionalDependencies map[string][]Dependency `toml:"optional-dependencies"`
	DevDependencies      map[string][]Dependency `toml:"dev-dependencies"`

	// ResolutionMarkers claim this entry for part of the environment space
	// when the resolution forked: the numpy for one Python version range
	// carries the markers telling it apart from the numpy for another.
	ResolutionMarkers []string `toml:"resolution-markers"`

	// Sdist and Wheels are the package's distribution artifacts. Hashes
	// live here: PyPI has no package-level hash, only per-artifact ones.
	Sdist  *Artifact  `toml:"sdist"`
	Wheels []Artifact `toml:"wheels"`
}

// Source says where a package comes from. Exactly one field is set.
type Source struct {
	// Registry is the index URL the package was resolved from.
	Registry string `toml:"registry"`

	// Virtual and Editable mark the project's own packages: Virtual a
	// package that is not installed (the usual project root), Editable one
	// installed in place (workspace members). Both hold the directory,
	// relative to the lock.
	Virtual  string `toml:"virtual"`
	Editable string `toml:"editable"`

	// Git, Path, Directory and URL are direct dependencies on a repository,
	// a local archive, a local directory, and a remote archive.
	Git       string `toml:"git"`
	Path      string `toml:"path"`
	Directory string `toml:"directory"`
	URL       string `toml:"url"`
}

// IsProject says whether the package is part of the project itself rather
// than something fetched: the roots of the dependency graph.
func (s *Source) IsProject() bool {
	return s.Virtual != "" || s.Editable != ""
}

// Dependency is one edge of the resolved graph.
type Dependency struct {
	Name string `toml:"name"`

	// Version and Source disambiguate the target when the resolution
	// forked: a lock holding numpy at three versions states which one this
	// edge points to. Both empty mean the name alone identifies it.
	Version string `toml:"version"`
	Source  Source `toml:"source"`

	// Extra lists the target's extras this dependency enables, as in
	// requests[socks].
	Extra []string `toml:"extra"`

	// Marker is the environment marker the edge is conditional on, empty
	// when it holds everywhere.
	Marker string `toml:"marker"`
}

// Artifact is one distribution file: a wheel or an sdist.
type Artifact struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
	Size int64  `toml:"size"`
}

// HashValue splits the artifact's hash into its algorithm and hex value.
// uv writes them as "sha256:abc...".
func (a *Artifact) HashValue() (algorithm, value string) {
	algorithm, value, found := strings.Cut(a.Hash, ":")
	if !found {
		return "", a.Hash
	}
	return algorithm, value
}

// ParseLockfile reads a uv.lock document.
func ParseLockfile(data []byte) (*Lockfile, error) {
	lock := &Lockfile{}
	if err := toml.Unmarshal(data, lock); err != nil {
		return nil, fmt.Errorf("parsing uv.lock: %w", err)
	}

	if lock.Version != lockVersion {
		return nil, fmt.Errorf(
			"uv.lock is schema version %d, this reader understands %d",
			lock.Version, lockVersion,
		)
	}

	// Names become identities everywhere downstream, so they are
	// normalized here and nowhere else has to wonder. uv writes them
	// normalized already; a hand-edited lock may not.
	for i := range lock.Packages {
		pkg := &lock.Packages[i]
		if pkg.Name == "" {
			return nil, fmt.Errorf("uv.lock package #%d has no name", i)
		}
		pkg.Name = NormalizeName(pkg.Name)
		normalizeDependencies(pkg.Dependencies)
		for _, deps := range pkg.OptionalDependencies {
			normalizeDependencies(deps)
		}
		for _, deps := range pkg.DevDependencies {
			normalizeDependencies(deps)
		}
	}

	return lock, nil
}

// ReadLockfile reads a uv.lock from a file.
func ReadLockfile(path string) (*Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParseLockfile(data)
}

func normalizeDependencies(deps []Dependency) {
	for i := range deps {
		deps[i].Name = NormalizeName(deps[i].Name)
		for j := range deps[i].Extra {
			deps[i].Extra[j] = NormalizeName(deps[i].Extra[j])
		}
	}
}

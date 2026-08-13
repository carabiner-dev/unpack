// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"os"
	"sort"

	"github.com/BurntSushi/toml"
)

// This file reads poetry.lock files, the lockfile Poetry writes next to a
// pyproject.toml. Like a uv lock it resolves every environment at once, but
// it says less: there is no entry for the project's own package and no
// record of its direct dependencies, both of which live in pyproject.toml,
// and a package appears at one version rather than forking per environment.

// The poetry.lock schema versions this reader understands: 2.0 is what
// Poetry 1.x writes, 2.1 what Poetry 2.x writes. The difference that
// matters here is that 2.0 records no group membership at all — it lives in
// the manifest — while 2.1 stamps every package with its groups.
var poetryLockVersions = map[string]bool{"2.0": true, "2.1": true}

// PoetryLockfile is a parsed poetry.lock.
type PoetryLockfile struct {
	Packages []PoetryPackage `toml:"package"`
	Metadata PoetryMetadata  `toml:"metadata"`
}

// PoetryMetadata is the lock's trailer.
type PoetryMetadata struct {
	LockVersion    string `toml:"lock-version"`
	PythonVersions string `toml:"python-versions"`
	ContentHash    string `toml:"content-hash"`
}

// PoetryPackage is one locked package.
type PoetryPackage struct {
	Name           string `toml:"name"`
	Version        string `toml:"version"`
	Description    string `toml:"description"`
	Optional       bool   `toml:"optional"`
	PythonVersions string `toml:"python-versions"`

	// Groups lists the dependency groups the package serves (lock 2.1).
	// Empty in a 2.0 lock, where membership is derived from the manifest.
	Groups []string `toml:"groups"`

	// markers says where the package applies at all. A package serving
	// several groups may apply to each under a different condition, so the
	// lock writes either one marker or a group-to-marker table; the parser
	// normalizes both into the table, the plain form under every group.
	RawMarkers any               `toml:"markers"`
	Markers    map[string]string `toml:"-"`

	// RawDependencies is the resolved dependency table: target name to a
	// constraint, which may be a bare version string, an object carrying a
	// marker and extras, or a list of such objects when the constraint
	// differs by environment. Dependencies is its normalized form.
	RawDependencies map[string]any     `toml:"dependencies"`
	Dependencies    []PoetryDependency `toml:"-"`

	// Extras names the package's extras and their requirements. The values
	// are requirement strings kept only for completeness: the packages an
	// enabled extra pulls in are resolved through Dependencies.
	Extras map[string][]string `toml:"extras"`

	// Files are the distribution artifacts with their hashes, named by
	// filename rather than URL.
	Files []PoetryFile `toml:"files"`

	// Source is set when the package does not come from an index.
	Source *PoetrySource `toml:"source"`
}

// PoetryDependency is one edge of the resolved graph, normalized.
type PoetryDependency struct {
	Name   string
	Marker string
	Extras []string
}

// PoetryFile is one distribution artifact.
type PoetryFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

// PoetrySource says where a non-index package comes from.
type PoetrySource struct {
	Type string `toml:"type"` // "git", "url", "directory", "legacy"
	URL  string `toml:"url"`

	// Reference is what was asked for (a branch, tag or rev) and
	// ResolvedReference the commit it resolved to.
	Reference         string `toml:"reference"`
	ResolvedReference string `toml:"resolved_reference"`
}

// ParsePoetryLockfile reads a poetry.lock document.
func ParsePoetryLockfile(data []byte) (*PoetryLockfile, error) {
	lock := &PoetryLockfile{}
	if err := toml.Unmarshal(data, lock); err != nil {
		return nil, fmt.Errorf("parsing poetry.lock: %w", err)
	}

	if !poetryLockVersions[lock.Metadata.LockVersion] {
		return nil, fmt.Errorf(
			"poetry.lock is schema version %q, this reader understands 2.0 and 2.1",
			lock.Metadata.LockVersion,
		)
	}

	for i := range lock.Packages {
		pkg := &lock.Packages[i]
		if pkg.Name == "" {
			return nil, fmt.Errorf("poetry.lock package #%d has no name", i)
		}
		pkg.Name = NormalizeName(pkg.Name)
		if err := pkg.normalize(); err != nil {
			return nil, fmt.Errorf("package %s: %w", pkg.Name, err)
		}
	}
	return lock, nil
}

// ReadPoetryLockfile reads a poetry.lock from a file.
func ReadPoetryLockfile(path string) (*PoetryLockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParsePoetryLockfile(data)
}

// normalize resolves the fields TOML admits several shapes for.
func (pkg *PoetryPackage) normalize() error {
	markers, err := normalizePoetryMarkers(pkg.RawMarkers, pkg.Groups)
	if err != nil {
		return err
	}
	pkg.Markers = markers
	pkg.RawMarkers = nil

	for name, constraint := range pkg.RawDependencies {
		deps, err := normalizePoetryDependency(name, constraint)
		if err != nil {
			return err
		}
		pkg.Dependencies = append(pkg.Dependencies, deps...)
	}
	pkg.RawDependencies = nil

	// Sorted by normalized name so the graph builds the same every run:
	// TOML tables have no order to preserve, and the raw spellings sort
	// differently than the canonical ones.
	sort.Slice(pkg.Dependencies, func(i, j int) bool {
		if pkg.Dependencies[i].Name != pkg.Dependencies[j].Name {
			return pkg.Dependencies[i].Name < pkg.Dependencies[j].Name
		}
		return pkg.Dependencies[i].Marker < pkg.Dependencies[j].Marker
	})
	return nil
}

// normalizePoetryMarkers reads the markers field: one marker for the whole
// package, or one per group.
func normalizePoetryMarkers(raw any, groups []string) (map[string]string, error) {
	switch value := raw.(type) {
	case nil:
		return nil, nil
	case string:
		// The plain form holds under every group the package serves, and
		// under the blank group when the lock does not record groups.
		markers := map[string]string{}
		for _, group := range groups {
			markers[group] = value
		}
		if len(groups) == 0 {
			markers[""] = value
		}
		return markers, nil
	case map[string]any:
		markers := make(map[string]string, len(value))
		for group, marker := range value {
			s, ok := marker.(string)
			if !ok {
				return nil, fmt.Errorf("the marker for group %q is not a string", group)
			}
			markers[group] = s
		}
		return markers, nil
	default:
		return nil, fmt.Errorf("unrecognized markers shape %T", raw)
	}
}

// normalizePoetryDependency reads one entry of the dependency table. The
// version constraints are dropped: the resolved versions live on the
// package entries, and the edge only has to name its target.
func normalizePoetryDependency(name string, raw any) ([]PoetryDependency, error) {
	switch value := raw.(type) {
	case string:
		// A bare constraint: unconditional edge.
		return []PoetryDependency{{Name: NormalizeName(name)}}, nil
	case map[string]any:
		return []PoetryDependency{poetryDependencyFromTable(name, value)}, nil
	case []map[string]any:
		// One entry per environment the constraint differs in.
		deps := make([]PoetryDependency, 0, len(value))
		for _, table := range value {
			deps = append(deps, poetryDependencyFromTable(name, table))
		}
		return deps, nil
	case []any:
		deps := make([]PoetryDependency, 0, len(value))
		for _, item := range value {
			table, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("dependency %q has an unrecognized constraint list", name)
			}
			deps = append(deps, poetryDependencyFromTable(name, table))
		}
		return deps, nil
	default:
		return nil, fmt.Errorf("dependency %q has an unrecognized shape %T", name, raw)
	}
}

func poetryDependencyFromTable(name string, table map[string]any) PoetryDependency {
	dep := PoetryDependency{Name: NormalizeName(name)}
	if marker, ok := table["markers"].(string); ok {
		dep.Marker = marker
	}
	if extras, ok := table["extras"].([]any); ok {
		for _, extra := range extras {
			if s, ok := extra.(string); ok {
				dep.Extras = append(dep.Extras, NormalizeName(s))
			}
		}
	}
	return dep
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// LockFile is the name of NuGet's lockfile, which a project has when it
// is restored with RestorePackagesWithLockFile.
const LockFile = "packages.lock.json"

// Types of an entry of the lockfile.
const (
	// TypeDirect is a package the project references itself.
	TypeDirect = "Direct"
	// TypeTransitive is a package another package brings in.
	TypeTransitive = "Transitive"
	// TypeCentralTransitive is a transitive package whose version the
	// repository pins centrally.
	TypeCentralTransitive = "CentralTransitive"
	// TypeProject is another project of the solution the project
	// references. It is no package and has no version.
	TypeProject = "Project"
)

// ErrMalformed is returned for a lockfile that cannot be read.
var ErrMalformed = errors.New("malformed packages.lock.json")

// Lock is a packages.lock.json: for each target the project is built
// for, the packages its dependency graph resolved to, with what each of
// them depends on.
type Lock struct {
	Version int
	Targets []*Target
}

// Target is the resolution for one target framework, and optionally one
// runtime.
type Target struct {
	// Name is the target as the lockfile keys it: the framework
	// ("net8.0", ".NETFramework,Version=v4.8"), followed for a runtime
	// by a slash and its identifier ("net8.0/win-x64"). A lockfile of
	// the third schema may key it by an alias, and states the framework
	// beside it.
	Name      string
	Framework string
	Runtime   string

	Entries []*Entry
}

// Entry is one package, or project, of a target.
type Entry struct {
	// ID is the package's id as the lockfile writes it. NuGet does not
	// tell ids apart by case.
	ID   string
	Type string

	// Requested is the range of versions asked for, of a package asked
	// for directly or pinned centrally, as "[13.0.1, )". Resolved is the
	// version it resolved to.
	Requested string
	Resolved  string

	// ContentHash is NuGet's hash of the package's content, in base64
	// (see PropertyContentHash).
	ContentHash string

	// Dependencies are what the entry depends on: ids, each with the
	// range it asks for.
	Dependencies []Dependency
}

// Dependency is one thing an entry depends on.
type Dependency struct {
	ID    string
	Range string
}

type rawEntry struct {
	Type         string             `json:"type"`
	Requested    string             `json:"requested"`
	Resolved     string             `json:"resolved"`
	ContentHash  string             `json:"contentHash"`
	Dependencies map[string]*string `json:"dependencies"`
}

// rawTarget is a target of the third schema.
type rawTarget struct {
	Framework    string               `json:"framework"`
	Dependencies map[string]*rawEntry `json:"dependencies"`
}

// aliasedSchema is the schema that moved the targets to the root of the
// document, to key them by alias.
const aliasedSchema = 3

// ReadLock reads a packages.lock.json.
func ReadLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", LockFile, err)
	}
	return ParseLock(data)
}

// ParseLock reads the contents of a packages.lock.json, in any of its
// schemas: the first two hold the targets under "dependencies", the
// third at the root of the document.
func ParseLock(data []byte) (*Lock, error) {
	// A byte order mark, which tools on Windows write.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	root := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	lock := &Lock{}
	if err := json.Unmarshal(root["version"], &lock.Version); err != nil || lock.Version < 1 {
		return nil, fmt.Errorf("%w: it states no schema version", ErrMalformed)
	}

	if lock.Version < aliasedSchema {
		targets := map[string]map[string]*rawEntry{}
		if raw, ok := root["dependencies"]; ok {
			if err := json.Unmarshal(raw, &targets); err != nil {
				return nil, fmt.Errorf("%w: reading its targets: %w", ErrMalformed, err)
			}
		}
		for name, entries := range targets {
			lock.Targets = append(lock.Targets, newTarget(name, "", entries))
		}
	} else {
		for name, raw := range root {
			if name == "version" {
				continue
			}
			target := &rawTarget{}
			// What is no target at the root is something a newer
			// NuGet added, and is passed over as NuGet does.
			if err := json.Unmarshal(raw, target); err != nil || target.Dependencies == nil {
				continue
			}
			lock.Targets = append(lock.Targets, newTarget(name, target.Framework, target.Dependencies))
		}
	}
	sort.Slice(lock.Targets, func(i, j int) bool { return lock.Targets[i].Name < lock.Targets[j].Name })
	return lock, nil
}

// newTarget builds a target from its key and its entries.
func newTarget(name, framework string, entries map[string]*rawEntry) *Target {
	target := &Target{Name: name, Framework: framework}
	base, runtime, _ := strings.Cut(name, "/")
	target.Runtime = runtime
	if target.Framework == "" {
		target.Framework = base
	}

	for id, raw := range entries {
		if raw == nil {
			continue
		}
		entry := &Entry{
			ID: id, Type: normalizeType(raw.Type),
			Requested: raw.Requested, Resolved: raw.Resolved, ContentHash: raw.ContentHash,
		}
		for depID, depRange := range raw.Dependencies {
			dep := Dependency{ID: depID}
			if depRange != nil {
				dep.Range = *depRange
			}
			entry.Dependencies = append(entry.Dependencies, dep)
		}
		sort.Slice(entry.Dependencies, func(i, j int) bool { return entry.Dependencies[i].ID < entry.Dependencies[j].ID })
		target.Entries = append(target.Entries, entry)
	}
	sort.Slice(target.Entries, func(i, j int) bool {
		return strings.ToLower(target.Entries[i].ID) < strings.ToLower(target.Entries[j].ID)
	})
	return target
}

// normalizeType reads an entry's type whatever its case, as NuGet does,
// and a type that is missing or unknown as Direct, which is NuGet's
// default.
func normalizeType(raw string) string {
	for _, known := range []string{TypeDirect, TypeTransitive, TypeCentralTransitive, TypeProject} {
		if strings.EqualFold(raw, known) {
			return known
		}
	}
	return TypeDirect
}

// Find returns the entry of a target with an id, whatever its case.
func (t *Target) Find(id string) *Entry {
	for _, entry := range t.Entries {
		if strings.EqualFold(entry.ID, id) {
			return entry
		}
	}
	return nil
}

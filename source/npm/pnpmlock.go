// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file reads pnpm-lock.yaml, in the two schema generations still in
// the wild: 6 (pnpm 8) and 9 (pnpm 9 onward). The differences are spelling,
// not substance — 6 prefixes package keys with a slash and keeps edges on
// the package entries, 9 moves the edges to a snapshots table and, for a
// single project, 6 states the direct dependencies at the top level where 9
// always writes an importers table — so the parser normalizes both into one
// shape and the graph builder never knows which it read.

// PnpmLock is a parsed pnpm-lock.yaml, normalized.
type PnpmLock struct {
	// LockfileVersion is the schema version the file declared.
	LockfileVersion string

	// Importers are the project's own packages: "." for the project
	// itself, one more per workspace member, keyed by their directory.
	Importers map[string]*PnpmImporter

	// Packages are the resolved third-party packages, keyed name@version.
	Packages map[string]*PnpmPackage
}

// PnpmImporter is one of the project's own packages, with its direct
// dependencies by kind. Values are version references: a resolved version,
// or link:<path> pointing at another importer.
type PnpmImporter struct {
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
}

// PnpmPackage is one resolved package.
type PnpmPackage struct {
	Name      string
	Version   string
	Integrity string
	Tarball   string

	// Dependencies and OptionalDependencies are the package's edges,
	// name to resolved version.
	Dependencies         map[string]string
	OptionalDependencies map[string]string
}

// rawPnpmLock is the file as YAML sees it, both generations at once.
type rawPnpmLock struct {
	LockfileVersion string                     `yaml:"lockfileVersion"`
	Importers       map[string]rawPnpmImporter `yaml:"importers"`

	// The flat form a version 6 single-project lock uses.
	Dependencies         map[string]rawPnpmImporterDep `yaml:"dependencies"`
	DevDependencies      map[string]rawPnpmImporterDep `yaml:"devDependencies"`
	OptionalDependencies map[string]rawPnpmImporterDep `yaml:"optionalDependencies"`

	Packages  map[string]rawPnpmPackage  `yaml:"packages"`
	Snapshots map[string]rawPnpmSnapshot `yaml:"snapshots"`
}

type rawPnpmImporter struct {
	Dependencies         map[string]rawPnpmImporterDep `yaml:"dependencies"`
	DevDependencies      map[string]rawPnpmImporterDep `yaml:"devDependencies"`
	OptionalDependencies map[string]rawPnpmImporterDep `yaml:"optionalDependencies"`
}

type rawPnpmImporterDep struct {
	Version string `yaml:"version"`
}

type rawPnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
	} `yaml:"resolution"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type rawPnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// ParsePnpmLock reads a pnpm-lock.yaml document.
func ParsePnpmLock(data []byte) (*PnpmLock, error) {
	raw := &rawPnpmLock{}
	if err := yaml.Unmarshal(data, raw); err != nil {
		return nil, fmt.Errorf("parsing pnpm-lock.yaml: %w", err)
	}

	major, _, _ := strings.Cut(raw.LockfileVersion, ".")
	if major != "6" && major != "9" {
		return nil, fmt.Errorf(
			"pnpm-lock.yaml is schema version %q, this reader understands 6 and 9",
			raw.LockfileVersion,
		)
	}

	lock := &PnpmLock{
		LockfileVersion: raw.LockfileVersion,
		Importers:       map[string]*PnpmImporter{},
		Packages:        map[string]*PnpmPackage{},
	}

	for dir, importer := range raw.Importers {
		lock.Importers[dir] = &PnpmImporter{
			Dependencies:         importerDeps(importer.Dependencies),
			DevDependencies:      importerDeps(importer.DevDependencies),
			OptionalDependencies: importerDeps(importer.OptionalDependencies),
		}
	}
	// A version 6 single-project lock has no importers table: its top
	// level is the one importer.
	if len(lock.Importers) == 0 {
		lock.Importers["."] = &PnpmImporter{
			Dependencies:         importerDeps(raw.Dependencies),
			DevDependencies:      importerDeps(raw.DevDependencies),
			OptionalDependencies: importerDeps(raw.OptionalDependencies),
		}
	}

	for key, entry := range raw.Packages {
		name, version, err := pnpmKeyParts(key)
		if err != nil {
			return nil, err
		}
		pkg := &PnpmPackage{
			Name:                 name,
			Version:              version,
			Integrity:            entry.Resolution.Integrity,
			Tarball:              entry.Resolution.Tarball,
			Dependencies:         pnpmVersionRefs(entry.Dependencies),
			OptionalDependencies: pnpmVersionRefs(entry.OptionalDependencies),
		}
		lock.Packages[name+"@"+version] = pkg
	}

	// Version 9 keeps the edges in snapshots; fold them onto the packages.
	for key, snapshot := range raw.Snapshots {
		name, version, err := pnpmKeyParts(key)
		if err != nil {
			return nil, err
		}
		pkg, ok := lock.Packages[name+"@"+version]
		if !ok {
			continue
		}
		pkg.Dependencies = pnpmVersionRefs(snapshot.Dependencies)
		pkg.OptionalDependencies = pnpmVersionRefs(snapshot.OptionalDependencies)
	}

	return lock, nil
}

// ReadPnpmLock reads a pnpm-lock.yaml from a directory.
func ReadPnpmLock(workDir string) (*PnpmLock, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "pnpm-lock.yaml"))
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParsePnpmLock(data)
}

// pnpmKeyParts splits a package key into name and version. Version 6 keys
// carry a leading slash, either generation may carry a parenthesized peer
// suffix, and a scoped name holds an @ of its own, so the version starts at
// the last @.
func pnpmKeyParts(key string) (name, version string, err error) {
	key = strings.TrimPrefix(key, "/")
	key = stripPeerSuffix(key)
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return "", "", fmt.Errorf("unparseable pnpm package key %q", key)
	}
	return key[:at], key[at+1:], nil
}

// stripPeerSuffix drops the parenthesized peer qualifiers pnpm appends to
// versions and keys: debug@4.4.3(supports-color@9.0.0) resolves the same
// package as debug@4.4.3.
func stripPeerSuffix(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}

// importerDeps flattens an importer's dependency table to name → version
// reference, peer suffixes stripped, link: references kept as they are.
func importerDeps(raw map[string]rawPnpmImporterDep) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	deps := make(map[string]string, len(raw))
	for name, dep := range raw {
		deps[name] = pnpmVersionRef(dep.Version)
	}
	return deps
}

func pnpmVersionRefs(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	refs := make(map[string]string, len(raw))
	for name, version := range raw {
		refs[name] = pnpmVersionRef(version)
	}
	return refs
}

func pnpmVersionRef(version string) string {
	if strings.HasPrefix(version, "link:") {
		return "link:" + path.Clean(strings.TrimPrefix(version, "link:"))
	}
	return stripPeerSuffix(version)
}

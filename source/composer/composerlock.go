// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package composer implements dependency extraction for PHP codebases
// managed by Composer. The lockfile is the richest in mainstream use:
// resolved versions, the dependency graph, licenses, descriptions,
// homepages and the exact git commit of every package are all in it, so
// extraction is offline and licenses need no enrichment at all.
package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ComposerLock is a parsed composer.lock.
type ComposerLock struct {
	// Packages are what the project needs; PackagesDev what development
	// additionally needs. The partition is Composer's own.
	Packages    []*ComposerPackage `json:"packages"`
	PackagesDev []*ComposerPackage `json:"packages-dev"`

	ContentHash string `json:"content-hash"`
}

// ComposerPackage is one locked package.
type ComposerPackage struct {
	// Name is vendor/name, Composer's two-part identity.
	Name    string `json:"name"`
	Version string `json:"version"`

	// Source is where the package's code lives — for registry packages a
	// git repository and the exact commit — and Dist the archive an
	// install downloads.
	Source ComposerSource `json:"source"`
	Dist   ComposerDist   `json:"dist"`

	// Require maps requirement names to constraints: the edges. Platform
	// requirements (php, extensions) appear here too, slash-less.
	Require map[string]string `json:"require"`

	License     []string `json:"license"`
	Description string   `json:"description"`
	Homepage    string   `json:"homepage"`
}

// ComposerSource points at a package's code.
type ComposerSource struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

// ComposerDist points at a package's installable archive.
type ComposerDist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`

	// Shasum is the archive's SHA-1 — when the registry states one, which
	// Packagist does not: its archives are built from the source commit,
	// and the commit is the integrity anchor.
	Shasum string `json:"shasum"`
}

// ParseComposerLock reads a composer.lock document.
func ParseComposerLock(data []byte) (*ComposerLock, error) {
	lock := &ComposerLock{}
	if err := json.Unmarshal(data, lock); err != nil {
		return nil, fmt.Errorf("parsing composer.lock: %w", err)
	}
	for _, pkg := range append(append([]*ComposerPackage{}, lock.Packages...), lock.PackagesDev...) {
		if pkg.Name == "" {
			return nil, fmt.Errorf("composer.lock holds a nameless package")
		}
	}
	return lock, nil
}

// ReadComposerLock reads a composer.lock from a directory.
func ReadComposerLock(workDir string) (*ComposerLock, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "composer.lock"))
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParseComposerLock(data)
}

// isPlatformRequirement says whether a requirement names the platform
// rather than a package: php itself, extensions, system libraries and the
// composer APIs. Real packages are vendor/name; platform names carry no
// slash.
func isPlatformRequirement(name string) bool {
	return !strings.Contains(name, "/")
}

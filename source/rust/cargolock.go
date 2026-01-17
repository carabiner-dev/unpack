// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// CargoLock represents the structure of a Cargo.lock file.
type CargoLock struct {
	Version  int            `toml:"version"`
	Packages []LockPackage  `toml:"package"`
	Metadata toml.Primitive `toml:"metadata"` // Ignored but captured to avoid parse errors
}

// LockPackage represents a package entry in Cargo.lock.
type LockPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source,omitempty"`
	Checksum     string   `toml:"checksum,omitempty"`
	Dependencies []string `toml:"dependencies,omitempty"`
}

// PackageKey uniquely identifies a package by name and version.
type PackageKey struct {
	Name    string
	Version string
}

func (pk PackageKey) String() string {
	return fmt.Sprintf("%s %s", pk.Name, pk.Version)
}

// ParseCargoLock parses a Cargo.lock file from the given directory.
func ParseCargoLock(dir string) (*CargoLock, error) {
	lockPath := filepath.Join(dir, "Cargo.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("reading Cargo.lock: %w", err)
	}

	return ParseCargoLockData(data)
}

// ParseCargoLockData parses Cargo.lock content from bytes.
func ParseCargoLockData(data []byte) (*CargoLock, error) {
	var lock CargoLock
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("parsing Cargo.lock: %w", err)
	}

	return &lock, nil
}

// BuildPackageIndex creates a map from package key to package for quick lookups.
// It also creates an index by name only for packages with unique names.
func (cl *CargoLock) BuildPackageIndex() (byKey map[PackageKey]*LockPackage, byName map[string][]*LockPackage) {
	byKey = make(map[PackageKey]*LockPackage)
	byName = make(map[string][]*LockPackage)

	for i := range cl.Packages {
		pkg := &cl.Packages[i]
		key := PackageKey{Name: pkg.Name, Version: pkg.Version}
		byKey[key] = pkg
		byName[pkg.Name] = append(byName[pkg.Name], pkg)
	}

	return byKey, byName
}

func (cl *CargoLock) FindRootPackages() []*LockPackage {
	var roots []*LockPackage
	for i := range cl.Packages {
		if cl.Packages[i].Source == "" {
			roots = append(roots, &cl.Packages[i])
		}
	}
	return roots
}

// ParseDependencyRef parses a dependency reference string from Cargo.lock.
// Dependencies can be in formats:
// - "name" (simple, when only one version exists)
// - "name version" (when multiple versions might exist)
// - "name version (source)" (with explicit source)
func ParseDependencyRef(dep string) (name, version string) {
	// Remove any source specification in parentheses
	if idx := strings.Index(dep, " ("); idx != -1 {
		dep = dep[:idx]
	}

	parts := strings.SplitN(dep, " ", 2)
	name = parts[0]
	if len(parts) > 1 {
		version = parts[1]
	}
	return name, version
}

// ResolveDependency resolves a dependency reference to a specific package.
// If version is empty and multiple versions exist, it returns the first one found.
func ResolveDependency(dep string, byKey map[PackageKey]*LockPackage, byName map[string][]*LockPackage) (*LockPackage, error) {
	name, version := ParseDependencyRef(dep)

	// If version is specified, look up by key
	if version != "" {
		key := PackageKey{Name: name, Version: version}
		if pkg, ok := byKey[key]; ok {
			return pkg, nil
		}
		return nil, fmt.Errorf("package %s@%s not found", name, version)
	}

	// If no version, look up by name
	pkgs, ok := byName[name]
	if !ok || len(pkgs) == 0 {
		return nil, fmt.Errorf("package %s not found", name)
	}

	// If only one version exists, return it
	if len(pkgs) == 1 {
		return pkgs[0], nil
	}

	// Multiple versions exist but no version specified - this shouldn't happen
	// in a valid Cargo.lock, but return the first one as fallback
	return pkgs[0], nil
}

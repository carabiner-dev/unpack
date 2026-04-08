// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PackageLock represents the structure of a package-lock.json file (v3 format).
type PackageLock struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	LockfileVersion int                    `json:"lockfileVersion"`
	Requires        bool                   `json:"requires"`
	Packages        map[string]LockPackage `json:"packages"`
}

// LockPackage represents a package entry in package-lock.json.
type LockPackage struct {
	Name                 string            `json:"name,omitempty"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved,omitempty"`
	Integrity            string            `json:"integrity,omitempty"`
	License              string            `json:"license,omitempty"`
	Dev                  bool              `json:"dev,omitempty"`
	Optional             bool              `json:"optional,omitempty"`
	Peer                 bool              `json:"peer,omitempty"`
	DevOptional          bool              `json:"devOptional,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`

	// For tracking during tree building
	path string
}

// PackageKey uniquely identifies a package by name and version.
type PackageKey struct {
	Name    string
	Version string
}

func (pk PackageKey) String() string {
	return fmt.Sprintf("%s@%s", pk.Name, pk.Version)
}

// ParsePackageLock parses a package-lock.json file from the given directory.
func ParsePackageLock(dir string) (*PackageLock, error) {
	lockPath := filepath.Join(dir, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("reading package-lock.json: %w", err)
	}

	return ParsePackageLockData(data)
}

// ParsePackageLockData parses package-lock.json content from bytes.
func ParsePackageLockData(data []byte) (*PackageLock, error) {
	var lock PackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	if lock.LockfileVersion < 2 {
		return nil, fmt.Errorf("unsupported lockfile version %d, need v2 or v3", lock.LockfileVersion)
	}

	// Store the path in each package for reference
	for path, pkg := range lock.Packages {
		pkg.path = path
		lock.Packages[path] = pkg
	}

	return &lock, nil
}

// GetRootPackage returns the root package (the one at key "").
func (pl *PackageLock) GetRootPackage() *LockPackage {
	if root, ok := pl.Packages[""]; ok {
		if root.Name == "" {
			root.Name = pl.Name
		}
		if root.Version == "" {
			root.Version = pl.Version
		}
		return &root
	}
	return nil
}

// ExtractPackageName extracts the package name from a node_modules path.
// e.g., "node_modules/@scope/package" -> "@scope/package"
// e.g., "node_modules/package" -> "package"
// e.g., "node_modules/a/node_modules/b" -> "b"
func ExtractPackageName(path string) string {
	if path == "" {
		return ""
	}

	// Find the last node_modules segment
	const prefix = "node_modules/"
	lastIdx := strings.LastIndex(path, prefix)
	if lastIdx == -1 {
		return path
	}

	return path[lastIdx+len(prefix):]
}

// BuildPackageIndex creates indexes for quick package lookups.
func (pl *PackageLock) BuildPackageIndex() (byKey map[PackageKey]*LockPackage, byName map[string][]*LockPackage, byPath map[string]*LockPackage) {
	byKey = make(map[PackageKey]*LockPackage)
	byName = make(map[string][]*LockPackage)
	byPath = make(map[string]*LockPackage)

	for path := range pl.Packages {
		pkg := pl.Packages[path]
		pkgCopy := pkg
		pkgCopy.path = path

		// Determine the package name
		name := pkgCopy.Name
		if name == "" {
			name = ExtractPackageName(path)
		}
		pkgCopy.Name = name

		if name == "" {
			// Skip root package for indexes
			continue
		}

		key := PackageKey{Name: name, Version: pkgCopy.Version}
		byKey[key] = &pkgCopy
		byName[name] = append(byName[name], &pkgCopy)
		byPath[path] = &pkgCopy
	}

	return byKey, byName, byPath
}

// ParseIntegrity parses an SRI integrity string and returns the algorithm and hash.
// e.g., "sha512-abc123..." -> ("sha512", []byte{...})
func ParseIntegrity(integrity string) (algorithm string, hash []byte, err error) {
	if integrity == "" {
		return "", nil, nil
	}

	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid integrity format: %s", integrity)
	}

	algorithm = parts[0]
	hash, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decoding integrity hash: %w", err)
	}

	return algorithm, hash, nil
}

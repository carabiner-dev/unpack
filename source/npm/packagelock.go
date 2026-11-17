// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

	// DevDependencies and PeerDependencies are stated for the project's
	// own packages, the root and the workspace members, as their
	// package.json declares them.
	DevDependencies  map[string]string `json:"devDependencies,omitempty"`
	PeerDependencies map[string]string `json:"peerDependencies,omitempty"`

	// Link marks an entry in node_modules that is a link to a directory
	// of the project, whose own entry is keyed by the path in Resolved:
	// a workspace member, or a dependency required by path.
	Link bool `json:"link,omitempty"`

	// Workspaces is the root entry's workspaces declaration, as written:
	// a list of patterns or an object holding one.
	Workspaces json.RawMessage `json:"workspaces,omitempty"`

	// For tracking during tree building
	path string
}

// isLocalDirectory says whether a lock key names a directory of the
// project rather than an installed package: a workspace member, or a
// dependency required by path.
func isLocalDirectory(key string) bool {
	return key != "" && !strings.HasPrefix(key, "node_modules/") && !strings.Contains(key, "/node_modules/")
}

// HasWorkspaces says whether the project declares workspaces.
func (pl *PackageLock) HasWorkspaces() bool {
	root, ok := pl.Packages[""]
	if !ok {
		return false
	}
	declared := strings.TrimSpace(string(root.Workspaces))
	return declared != "" && declared != "null" && declared != "[]" && declared != "{}"
}

// WorkspaceMembers returns the lock keys of the project's workspace
// members, sorted: the directories of the project the lock holds an entry
// for. The lock does not tell a member from a directory required by path,
// so in a project with workspaces each such directory is taken for one,
// and in a project without there are none.
func (pl *PackageLock) WorkspaceMembers() []string {
	if !pl.HasWorkspaces() {
		return nil
	}
	members := []string{}
	for key := range pl.Packages {
		if isLocalDirectory(key) && !pl.Packages[key].Link {
			members = append(members, key)
		}
	}
	sort.Strings(members)
	return members
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
	for key := range lock.Packages {
		pkg := lock.Packages[key]
		pkg.path = key
		lock.Packages[key] = pkg
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

		// Determine the package name. A directory of the project is
		// named in its entry unless the name is the directory's own.
		name := pkgCopy.Name
		if name == "" {
			if isLocalDirectory(path) {
				name = pathBase(path)
			} else {
				name = ExtractPackageName(path)
			}
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

// pathBase returns the last element of a lock key, which is
// slash-separated on every platform.
func pathBase(key string) string {
	return key[strings.LastIndex(key, "/")+1:]
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

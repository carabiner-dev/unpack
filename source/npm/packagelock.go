// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"
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
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved,omitempty"`
	Integrity    string            `json:"integrity,omitempty"`
	License      string            `json:"license,omitempty"`
	Dev          bool              `json:"dev,omitempty"`
	Optional     bool              `json:"optional,omitempty"`
	Peer         bool              `json:"peer,omitempty"`
	DevOptional  bool              `json:"devOptional,omitempty"`
	Dependencies map[string]string `json:"dependencies,omitempty"`

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

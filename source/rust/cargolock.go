// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"fmt"

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

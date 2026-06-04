// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"io/fs"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// SystemDecomposer extracts installed-package data from a system's
// filesystem. It extends api.Decomposer so decomposers can be registered
// through the shared registry while exposing a filesystem-aware Extract path
// that the SystemPackages unpacker uses.
//
// Implementations look for an installed-package database under the FS root
// (for RPM that is var/lib/rpm/...) and return its contents as a NodeList.
type SystemDecomposer interface {
	api.Decomposer

	// ExtractFromFS reads installed-package data from source and returns it as
	// a protobom NodeList. The FS root is the system's root, so paths are
	// looked up relative to it (e.g. "var/lib/rpm/Packages"). Returning
	// (nil, nil) means the decomposer's database is not present on this
	// system, which is not an error.
	ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error)
}

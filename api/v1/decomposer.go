// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/unpack/code"
)

// Decomposer is an interface that abstracts the logic of dependency extraction
// from a codebase.
type Decomposer interface {
	Extract(*DecomposerOptions) (*sbom.NodeList, error)
	Requirements(*DecomposerOptions) []Requirement
	DefaultOptions() any
}

// SourceDecomposer is a decomposer that reads data from a codebase.
type SourceDecomposer interface {
	// FindCodeBases reads a path index and locates any directories that
	// contain a codebase that a decomposer understands. Typically this
	// will be the root directory, but there may be cases where a directory
	// contains many, for example in a monorepo structure.
	FindCodeBases(*code.PathIndex) ([]string, error)
}

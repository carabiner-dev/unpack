// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var _ api.Decomposer = (*Decomposer)(nil)

func New() *Decomposer {
	return &Decomposer{}
}

type Decomposer struct{}

// Options configures the npm dependency extraction.
type Options struct {
	// IncludeDevDependencies includes dev dependencies in the output.
	IncludeDevDependencies bool

	// IncludeOptionalDependencies includes optional dependencies in the output.
	IncludeOptionalDependencies bool

	// IncludePeerDependencies includes peer dependencies in the output.
	IncludePeerDependencies bool
}

// DefaultOptions returns the default options for the npm decomposer.
func (d *Decomposer) DefaultOptions() any {
	return Options{
		IncludeDevDependencies:      false,
		IncludeOptionalDependencies: false,
		IncludePeerDependencies:     false,
	}
}

// Requirements returns the requirements for the decomposer.
// No external binary required - uses pure Go implementation.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement {
	return nil
}

// Extract parses package.json and package-lock.json files and builds the complete
// dependency graph as a protobom NodeList.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	// Parse package.json
	packageJSON, err := ParsePackageJSON(workDir)
	if err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	// Parse package-lock.json
	packageLock, err := ParsePackageLock(workDir)
	if err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	// Build the dependency tree
	tree := NewDependencyTree(packageJSON, packageLock)

	// Build the protobom NodeList
	nl, err := tree.Build(opts)
	if err != nil {
		return nil, fmt.Errorf("building dependency graph: %w", err)
	}

	return nl, nil
}

// FindCodeBases locates npm codebases by looking for package-lock.json files.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("package-lock.json")
}

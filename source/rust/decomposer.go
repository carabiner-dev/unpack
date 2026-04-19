// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

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

// Options configures the Rust dependency extraction.
type Options struct {
	// IncludeDevDependencies includes dev dependencies in the output.
	IncludeDevDependencies bool

	// IncludeBuildDependencies includes build dependencies in the output.
	IncludeBuildDependencies bool

	// Concurrency controls the number of parallel HTTP requests to crates.io (default: 10).
	Concurrency int
}

// DefaultOptions returns the default options for the Rust decomposer.
func (d *Decomposer) DefaultOptions() any {
	return Options{
		IncludeDevDependencies:   false,
		IncludeBuildDependencies: false,
	}
}

// Requirements returns the requirements for the decomposer.
// No external binary required - uses pure Go implementation.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement {
	return nil
}

// Extract parses Cargo.toml and Cargo.lock files and builds the complete
// dependency graph as a protobom NodeList.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	// Parse Cargo.toml
	cargoToml, err := ParseCargoToml(workDir)
	if err != nil {
		return nil, fmt.Errorf("parsing Cargo.toml: %w", err)
	}

	// Parse Cargo.lock
	cargoLock, err := ParseCargoLock(workDir)
	if err != nil {
		return nil, fmt.Errorf("parsing Cargo.lock: %w", err)
	}

	// Get decomposer-specific options
	dOpts := d.getOptions(opts)

	// Build the dependency tree
	tree := NewDependencyTree(cargoToml, cargoLock)

	// Build the protobom NodeList
	nl, err := tree.Build(opts)
	if err != nil {
		return nil, fmt.Errorf("building dependency graph: %w", err)
	}

	// Enrich dependency nodes with metadata from crates.io
	client := NewCratesIOClient(dOpts.Concurrency)
	tree.Enrich(client)

	return nl, nil
}

// getOptions extracts Rust-specific options from DecomposerOptions.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	defaultOpts := Options{Concurrency: defaultConcurrency}
	return &defaultOpts
}

// FindCodeBases locates Rust codebases by looking for Cargo.lock files.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("Cargo.lock")
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"fmt"
	"path/filepath"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var _ api.Decomposer = (*Decomposer)(nil)

// New returns a new Maven decomposer.
func New() *Decomposer {
	return &Decomposer{}
}

// Decomposer extracts dependency data from Maven projects.
type Decomposer struct{}

// Options configures the Maven dependency extraction.
type Options struct {
	RepoURL         string // Maven repository URL (default: https://repo1.maven.org/maven2)
	Concurrency     int    // Number of parallel HTTP requests (default: 10)
	IncludeTest     bool   // Include test-scoped dependencies (default: false)
	IncludeProvided bool   // Include provided-scoped dependencies (default: false)
	IncludeOptional bool   // Include optional dependencies (default: false)
}

var defaultOptions = Options{
	RepoURL:     defaultRepoURL,
	Concurrency: defaultConcurrency,
}

// DefaultOptions returns the default options for the Maven decomposer.
func (d *Decomposer) DefaultOptions() any {
	return defaultOptions
}

// Requirements returns external tool requirements.
// The Maven decomposer requires no external binaries.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement {
	return nil
}

// Extract parses the local pom.xml, resolves dependencies from Maven Central,
// and builds the complete dependency graph as a protobom NodeList.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	dOpts := d.getOptions(opts)

	// 1. Parse local pom.xml
	pom, err := ParsePomXML(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}

	// 2. Create resolver for fetching remote POMs
	resolver := NewResolver(dOpts)

	// 3. Resolve effective POM (parent chain + BOM imports + interpolation)
	effective, err := resolver.ResolveEffectivePOM(pom)
	if err != nil {
		return nil, fmt.Errorf("resolving effective POM: %w", err)
	}

	// 4. Build dependency tree
	dt := NewDependencyTree(effective, resolver, dOpts)
	if err := dt.Build(); err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}

	// 5. Convert to NodeList
	nl, err := dt.ToNodeList(opts)
	if err != nil {
		return nil, fmt.Errorf("converting to nodelist: %w", err)
	}

	return nl, nil
}

// FindCodeBases locates directories containing pom.xml files.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("pom.xml")
}

// getOptions extracts Maven-specific options from DecomposerOptions.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	return &defaultOptions
}

// CanDecompose checks if a directory contains a Maven project.
func CanDecompose(dir string) bool {
	_, err := ParsePomXML(filepath.Clean(dir))
	return err == nil
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
	"github.com/carabiner-dev/unpack/internal/logging"
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
	Concurrency     int    // Number of parallel HTTP requests (default: 5)
	IncludeTest     bool   // Include test-scoped dependencies (default: false)
	IncludeProvided bool   // Include provided-scoped dependencies (default: false)
	IncludeOptional bool   // Include optional dependencies (default: false)
	IncludeBuild    bool   // Include build plugins as build dependencies (default: false)
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

// Extract is ExtractWithContext with a background context, for a caller
// that has none to give.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractWithContext(context.Background(), opts)
}

var _ api.ContextDecomposer = (*Decomposer)(nil)

// ExtractWithContext parses the local pom.xml, resolves dependencies from Maven Central,
// and builds the complete dependency graph as a protobom NodeList.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	dOpts := d.getOptions(opts)

	// Apply common dependency inclusion options
	if opts.IncludeDev {
		dOpts.IncludeTest = true
	}
	if opts.IncludeBuild {
		dOpts.IncludeBuild = true
	}
	if opts.IncludeOptional {
		dOpts.IncludeOptional = true
	}

	// 1. Parse local pom.xml
	pom, err := ParsePomXML(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}

	// 2. Create resolver for fetching remote POMs (requires networking)
	var resolver *Resolver
	if opts.Networking >= api.NetworkEssential {
		resolver = NewResolver(dOpts)
	}

	// 3. Resolve effective POM (parent chain + BOM imports + interpolation)
	// A parent is read from the source tree when it is there, as in a
	// multi-module project, and from the repository otherwise.
	pomDir := opts.WorkDir
	if pomDir == "" {
		pomDir = "."
	}
	var effective *POM
	if resolver != nil {
		effective, err = resolver.ResolveEffectivePOMIn(pom, pomDir)
	} else {
		// Without the network there is no repository to read a parent
		// or a BOM from, but what the source tree states still stands:
		// the POM's own properties and dependency management, and those
		// of the parents beside it.
		effective, err = ResolveLocalEffectivePOM(pom, pomDir)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving effective POM: %w", err)
	}

	// 4. Build dependency tree. Without a resolver it stops at what the
	// POM declares: the dependencies of those live in POMs of their own,
	// which only the repository has.
	dt := NewDependencyTree(effective, resolver, dOpts)
	if resolver == nil {
		logging.FromContext(ctx).Debug("maven: networking is disabled, the graph holds only the dependencies pom.xml declares",
			"pom", filepath.Join(opts.WorkDir, "pom.xml"))
	}
	if err := dt.Build(); err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}

	// 5. Add build plugins if requested
	if dOpts.IncludeBuild {
		dt.AddBuildPlugins()
	}

	// 6. Fetch artifact hashes (essential: checksum files; full: download+compute)
	if opts.Networking >= api.NetworkEssential {
		dt.FetchHashes(opts.Networking >= api.NetworkFull)
	}

	// 7. Convert to NodeList
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

var _ api.ContextReporter = (*Decomposer)(nil)

// GenerationContext says in what context the decomposer's data is read:
// pom.xml, as it stands in the source tree, and the POMs it leads to.
func (d *Decomposer) GenerationContext() api.GenerationContext {
	return api.ContextSource
}

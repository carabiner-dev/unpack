// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

	// IgnoreNodeModulesCodebases instructs the decomposer to ignore any codebases
	// in node_modules directories (package-lock files from pulled dependencies)
	IgnoreNodeModulesCodebases bool
}

// DefaultOptions returns the default options for the npm decomposer.
func (d *Decomposer) DefaultOptions() any {
	return Options{
		IncludeDevDependencies:      false,
		IncludeOptionalDependencies: false,
		IncludePeerDependencies:     false,
		IgnoreNodeModulesCodebases:  true,
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

	// A codebase holding several lockfiles is read from npm's own first:
	// package-lock.json is the format this decomposer grew up on.
	switch {
	case fileExists(filepath.Join(workDir, "package-lock.json")):
		return d.extractNpm(workDir, opts)
	case fileExists(filepath.Join(workDir, "pnpm-lock.yaml")):
		return d.extractPnpm(workDir, opts)
	default:
		return nil, fmt.Errorf("no supported JavaScript lockfile in %s", workDir)
	}
}

// extractNpm builds the graph from package-lock.json.
func (d *Decomposer) extractNpm(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
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

// extractPnpm builds the graph from pnpm-lock.yaml.
func (d *Decomposer) extractPnpm(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	lock, err := ReadPnpmLock(workDir)
	if err != nil {
		return nil, err
	}
	return buildPnpmTree(lock, workDir, opts)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// FindCodeBases locates JavaScript codebases by their lockfiles. Lockfiles
// vendored under node_modules belong to installed dependencies, not to the
// codebase, and are skipped.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	locations := map[string]bool{}
	for _, lockfile := range []string{"package-lock.json", "pnpm-lock.yaml"} {
		found, err := index.FindFileLocations(lockfile)
		if err != nil {
			return nil, err
		}
		for _, dir := range found {
			if insideNodeModules(dir) {
				continue
			}
			locations[dir] = true
		}
	}
	dirs := make([]string, 0, len(locations))
	for dir := range locations {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// insideNodeModules says whether a path has a node_modules segment.
func insideNodeModules(dir string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(dir), "/") {
		if segment == "node_modules" {
			return true
		}
	}
	return false
}

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
	case fileExists(filepath.Join(workDir, "yarn.lock")):
		return d.extractYarn(workDir, opts)
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

	enrichFromRegistry(nl, opts, nil)
	return nl, nil
}

// enrichFromRegistry adds what the public npm registry knows about the
// graph's packages, when networking allows. public says which packages
// are the public registry's to describe; nil is for the locks that state
// where each package was fetched from, where that settles it.
func enrichFromRegistry(nl *sbom.NodeList, opts *api.DecomposerOptions, public func(*sbom.Node) bool) {
	if opts.Networking < api.NetworkEssential {
		return
	}
	if public == nil {
		public = fromPublicRegistry
	}
	NewRegistryClient(0).enrichNodes(nl, public)
}

// pnpmPublic says which packages of a pnpm graph come from the public
// registry. The lock records a download location only for what does not
// come from the project's registry, a tarball or a repository, and that
// location then settles it. For the rest it is the project's
// configuration that says which registry that is.
func pnpmPublic(workDir string) func(*sbom.Node) bool {
	config := pnpmRegistryConfig(workDir)
	return func(node *sbom.Node) bool {
		if node.GetUrlDownload() != "" {
			return fromPublicRegistry(node)
		}
		return config.public(node.GetName())
	}
}

// berryPublic says which packages of a Yarn berry graph come from the
// public registry: those the lock resolves through the npm protocol,
// when the project's configuration points that at the public registry.
// A patched package, or one from a repository or a directory, is not the
// registry's as it stands.
func berryPublic(lock *YarnBerryLock, workDir string) func(*sbom.Node) bool {
	config := yarnRegistryConfig(workDir)
	fromRegistry := map[PackageKey]struct{}{}
	for _, pkg := range lock.Entries {
		if pkg.FromNpm {
			fromRegistry[PackageKey{Name: pkg.Name, Version: pkg.Version}] = struct{}{}
		}
	}
	return func(node *sbom.Node) bool {
		_, ok := fromRegistry[PackageKey{Name: node.GetName(), Version: node.GetVersion()}]
		return ok && config.public(node.GetName())
	}
}

// extractPnpm builds the graph from pnpm-lock.yaml.
func (d *Decomposer) extractPnpm(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	lock, err := ReadPnpmLock(workDir)
	if err != nil {
		return nil, err
	}
	nl, err := buildPnpmTree(lock, workDir, opts)
	if err != nil {
		return nil, err
	}
	enrichFromRegistry(nl, opts, pnpmPublic(workDir))
	return nl, nil
}

// extractYarn builds the graph from a yarn.lock, whichever generation
// wrote it: both spell the file the same, so the content decides. The
// manifests carry what neither generation's lock does: the project's
// identity and the kind of each direct dependency.
func (d *Decomposer) extractYarn(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "yarn.lock"))
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	if IsYarnBerry(data) {
		lock, err := ParseYarnBerryLock(data)
		if err != nil {
			return nil, err
		}
		nl, err := buildYarnBerryTree(lock, workDir, opts)
		if err != nil {
			return nil, err
		}
		enrichFromRegistry(nl, opts, berryPublic(lock, workDir))
		return nl, nil
	}

	lock, err := ParseYarnLock(data)
	if err != nil {
		return nil, err
	}
	manifest, err := ParsePackageJSON(workDir)
	if err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}
	nl, err := buildYarnTree(lock, manifest, opts)
	if err != nil {
		return nil, err
	}
	enrichFromRegistry(nl, opts, nil)
	return nl, nil
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
	for _, lockfile := range []string{"package-lock.json", "pnpm-lock.yaml", "yarn.lock"} {
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

var _ api.ContextReporter = (*Decomposer)(nil)

// GenerationContext says in what context the decomposer's data is read:
// a lock file and its manifests, as they stand in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext {
	return api.ContextSource
}

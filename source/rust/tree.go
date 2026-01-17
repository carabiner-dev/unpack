// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// TODO(puerco): Enrich from https://crates.io/api/v1/crates/quote/1.0.35

// DependencyTree builds a complete dependency graph from Cargo files.
type DependencyTree struct {
	cargoToml *CargoToml
	cargoLock *CargoLock

	// Indexes for quick lookup
	pkgByKey  map[PackageKey]*LockPackage
	pkgByName map[string][]*LockPackage

	// Direct dependency types from Cargo.toml
	directDeps map[string]DependencyType

	// Cache of created nodes by package key
	nodeCache map[PackageKey]*sbom.Node
}

// NewDependencyTree creates a new dependency tree from parsed Cargo files.
func NewDependencyTree(toml *CargoToml, lock *CargoLock) *DependencyTree {
	pkgByKey, pkgByName := lock.BuildPackageIndex()

	return &DependencyTree{
		cargoToml:  toml,
		cargoLock:  lock,
		pkgByKey:   pkgByKey,
		pkgByName:  pkgByName,
		directDeps: toml.GetDirectDependencies(),
		nodeCache:  make(map[PackageKey]*sbom.Node),
	}
}

// Build constructs the complete dependency graph as a protobom NodeList.
func (dt *DependencyTree) Build(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()

	// Find the root package(s) - local packages without a source
	roots := dt.cargoLock.FindRootPackages()
	if len(roots) == 0 {
		return nil, fmt.Errorf("no root package found in Cargo.lock")
	}

	// Process each root package
	for _, root := range roots {
		rootKey := PackageKey{Name: root.Name, Version: root.Version}

		// Create root node
		rootNode := dt.createNode(root)

		// Apply version/commit info from options
		if opts.Version != "" {
			rootNode.Version = opts.Version
			rootNode.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = fmt.Sprintf("pkg:cargo/%s@%s", root.Name, opts.Version)
		}

		if opts.CommitHash != "" {
			rootNode.ExternalReferences = append(rootNode.ExternalReferences, &sbom.ExternalReference{
				Hashes: map[int32]string{
					int32(sbom.HashAlgorithm_SHA1): opts.CommitHash,
				},
				Type: sbom.ExternalReference_VCS,
			})
		}

		nl.AddRootNode(rootNode)
		dt.nodeCache[rootKey] = rootNode

		// Build the dependency tree recursively
		visited := make(map[PackageKey]bool)
		if err := dt.buildSubtree(nl, root, rootNode, visited); err != nil {
			return nil, fmt.Errorf("building dependency tree: %w", err)
		}
	}

	return nl, nil
}

// buildSubtree recursively builds the dependency subtree for a package.
func (dt *DependencyTree) buildSubtree(nl *sbom.NodeList, pkg *LockPackage, parentNode *sbom.Node, visited map[PackageKey]bool) error {
	pkgKey := PackageKey{Name: pkg.Name, Version: pkg.Version}

	// Mark as visited to handle cycles
	if visited[pkgKey] {
		return nil
	}
	visited[pkgKey] = true

	// Process each dependency
	for _, depRef := range pkg.Dependencies {
		depPkg, err := ResolveDependency(depRef, dt.pkgByKey, dt.pkgByName)
		if err != nil {
			// Skip unresolved dependencies - they might be platform-specific
			continue
		}

		depKey := PackageKey{Name: depPkg.Name, Version: depPkg.Version}

		// Get or create node for this dependency
		depNode, exists := dt.nodeCache[depKey]
		if !exists {
			depNode = dt.createNode(depPkg)
			dt.nodeCache[depKey] = depNode
		}

		// Determine the edge type based on how we reached this dependency
		edgeType := dt.determineEdgeType(pkg, depPkg)

		// Relate the dependency to its parent
		if err := nl.RelateNodeAtID(depNode, parentNode.GetId(), edgeType); err != nil {
			return fmt.Errorf("relating %s to %s: %w", depPkg.Name, pkg.Name, err)
		}

		// Recursively process this dependency's dependencies
		if !exists {
			if err := dt.buildSubtree(nl, depPkg, depNode, visited); err != nil {
				return err
			}
		}
	}

	return nil
}

// determineEdgeType determines the edge type for a dependency relationship.
// If the dependency is a direct dependency of the root, use its declared type.
// Otherwise, inherit the type from the parent or default to dependsOn.
func (dt *DependencyTree) determineEdgeType(_, dep *LockPackage) sbom.Edge_Type {
	// Check if this is a direct dependency from the root
	//nolint:exhaustive
	if depType, isDirect := dt.directDeps[dep.Name]; isDirect {
		switch depType {
		case DepTypeDev:
			return sbom.Edge_devDependency
		case DepTypeBuild:
			return sbom.Edge_buildDependency
		default:
			return sbom.Edge_dependsOn
		}
	}

	// For transitive dependencies, use dependsOn
	return sbom.Edge_dependsOn
}

// createNode creates a protobom Node for a Cargo package.
func (dt *DependencyTree) createNode(pkg *LockPackage) *sbom.Node {
	purl := fmt.Sprintf("pkg:cargo/%s@%s", pkg.Name, pkg.Version)

	node := &sbom.Node{
		Id:          uuid.NewString(),
		Type:        sbom.Node_PACKAGE,
		Name:        pkg.Name,
		Version:     pkg.Version,
		FileName:    pkg.Name,
		UrlDownload: fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s/download", pkg.Name, pkg.Version),
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl,
		},
		PrimaryPurpose: []sbom.Purpose{
			sbom.Purpose_LIBRARY,
		},
	}

	// Add checksum if available
	if pkg.Checksum != "" {
		node.Hashes = map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): pkg.Checksum,
		}
	}

	return node
}

// GetDependencyCount returns the total number of dependencies.
func (dt *DependencyTree) GetDependencyCount() int {
	return len(dt.cargoLock.Packages)
}

// GetDirectDependencyCount returns the number of direct dependencies.
func (dt *DependencyTree) GetDirectDependencyCount() int {
	return len(dt.directDeps)
}

// ListDependencies returns a sorted list of all dependencies for debugging/testing.
func (dt *DependencyTree) ListDependencies() []string {
	deps := make([]string, 0, len(dt.cargoLock.Packages))
	for _, pkg := range dt.cargoLock.Packages {
		deps = append(deps, fmt.Sprintf("%s@%s", pkg.Name, pkg.Version))
	}
	sort.Strings(deps)
	return deps
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// DependencyTree builds a complete dependency graph from npm package files.
type DependencyTree struct {
	packageJSON *PackageJSON
	packageLock *PackageLock

	// Indexes for quick lookup
	pkgByKey  map[PackageKey]*LockPackage
	pkgByName map[string][]*LockPackage
	pkgByPath map[string]*LockPackage

	// Direct dependency types from package.json
	directDeps map[string]DependencyType

	// Cache of created nodes by package path
	nodeCache map[string]*sbom.Node
}

// NewDependencyTree creates a new dependency tree from parsed npm package files.
func NewDependencyTree(pkg *PackageJSON, lock *PackageLock) *DependencyTree {
	byKey, byName, byPath := lock.BuildPackageIndex()

	return &DependencyTree{
		packageJSON: pkg,
		packageLock: lock,
		pkgByKey:    byKey,
		pkgByName:   byName,
		pkgByPath:   byPath,
		directDeps:  pkg.GetDirectDependencies(),
		nodeCache:   make(map[string]*sbom.Node),
	}
}

// Build constructs the complete dependency graph as a protobom NodeList.
func (dt *DependencyTree) Build(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()

	// Get the root package
	root := dt.packageLock.GetRootPackage()
	if root == nil {
		return nil, fmt.Errorf("no root package found in package-lock.json")
	}

	// Create root node
	rootNode := dt.createRootNode(root, opts)
	nl.AddRootNode(rootNode)
	dt.nodeCache[""] = rootNode

	// Build the dependency tree from the root's direct dependencies
	visited := make(map[string]bool)
	if err := dt.buildFromRoot(nl, rootNode, visited); err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}

	return nl, nil
}

// buildFromRoot builds the dependency tree starting from direct dependencies.
func (dt *DependencyTree) buildFromRoot(nl *sbom.NodeList, rootNode *sbom.Node, visited map[string]bool) error {
	// Process direct dependencies from package.json
	for depName, depType := range dt.directDeps {
		depPath := dt.resolveDependencyPath("", depName)
		if depPath == "" {
			continue
		}

		depPkg, ok := dt.pkgByPath[depPath]
		if !ok {
			continue
		}

		// Create or get node for this dependency
		depNode, exists := dt.nodeCache[depPath]
		if !exists {
			depNode = dt.createNode(depPkg)
			dt.nodeCache[depPath] = depNode
		}

		// Determine edge type based on dependency type
		edgeType := dt.depTypeToEdgeType(depType)

		// Relate the dependency to root
		if err := nl.RelateNodeAtID(depNode, rootNode.GetId(), edgeType); err != nil {
			return fmt.Errorf("relating %s to root: %w", depName, err)
		}

		// Recursively process this dependency's dependencies
		if !exists && !visited[depPath] {
			if err := dt.buildSubtree(nl, depPkg, depNode, depPath, visited); err != nil {
				return err
			}
		}
	}

	return nil
}

// buildSubtree recursively builds the dependency subtree for a package.
func (dt *DependencyTree) buildSubtree(nl *sbom.NodeList, pkg *LockPackage, parentNode *sbom.Node, parentPath string, visited map[string]bool) error {
	// Mark as visited to handle cycles
	if visited[parentPath] {
		return nil
	}
	visited[parentPath] = true

	// Get the package's dependencies from the lock file
	if pkg.Dependencies == nil {
		return nil
	}

	// Sort dependency names for deterministic output
	depNames := make([]string, 0, len(pkg.Dependencies))
	for name := range pkg.Dependencies {
		depNames = append(depNames, name)
	}
	sort.Strings(depNames)

	// Process each dependency
	for _, depName := range depNames {
		depPath := dt.resolveDependencyPath(parentPath, depName)
		if depPath == "" {
			continue
		}

		depPkg, ok := dt.pkgByPath[depPath]
		if !ok {
			continue
		}

		// Get or create node for this dependency
		depNode, exists := dt.nodeCache[depPath]
		if !exists {
			depNode = dt.createNode(depPkg)
			dt.nodeCache[depPath] = depNode
		}

		// All transitive dependencies use dependsOn edge type
		if err := nl.RelateNodeAtID(depNode, parentNode.GetId(), sbom.Edge_dependsOn); err != nil {
			return fmt.Errorf("relating %s to %s: %w", depName, pkg.Name, err)
		}

		// Recursively process this dependency's dependencies
		if !exists {
			if err := dt.buildSubtree(nl, depPkg, depNode, depPath, visited); err != nil {
				return err
			}
		}
	}

	return nil
}

// resolveDependencyPath finds the actual path where a dependency is installed.
// npm hoists packages to the highest possible level, so we need to search up.
func (dt *DependencyTree) resolveDependencyPath(parentPath, depName string) string {
	// Start from the parent's node_modules and work up
	searchPath := parentPath
	for {
		candidatePath := searchPath
		if candidatePath == "" {
			candidatePath = "node_modules/" + depName
		} else {
			candidatePath = searchPath + "/node_modules/" + depName
		}

		if _, ok := dt.pkgByPath[candidatePath]; ok {
			return candidatePath
		}

		// Move up one level
		if searchPath == "" {
			break
		}

		// Find the parent path (strip the last /node_modules/xxx part)
		idx := strings.LastIndex(searchPath, "/node_modules/")
		if idx == -1 {
			// We're at the top level node_modules
			searchPath = ""
		} else {
			searchPath = searchPath[:idx]
		}
	}

	return ""
}

// depTypeToEdgeType converts a DependencyType to an sbom.Edge_Type.
func (dt *DependencyTree) depTypeToEdgeType(depType DependencyType) sbom.Edge_Type {
	//nolint:exhaustive
	switch depType {
	case DepTypeDev:
		return sbom.Edge_devDependency
	case DepTypeOptional:
		return sbom.Edge_optionalDependency
	default:
		return sbom.Edge_dependsOn
	}
}

// createRootNode creates a protobom Node for the root package.
func (dt *DependencyTree) createRootNode(pkg *LockPackage, opts *api.DecomposerOptions) *sbom.Node {
	name := pkg.Name
	if name == "" {
		name = dt.packageJSON.Name
	}

	version := pkg.Version
	if opts.Version != "" {
		version = opts.Version
	} else if version == "" {
		version = dt.packageJSON.Version
	}

	purl := buildPURL(name, version)

	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl,
		},
		PrimaryPurpose: []sbom.Purpose{
			sbom.Purpose_APPLICATION,
		},
	}

	// Add commit hash if provided
	if opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{
				int32(sbom.HashAlgorithm_SHA1): opts.CommitHash,
			},
			Type: sbom.ExternalReference_VCS,
		})
	}

	// Add license if available
	if dt.packageJSON.License != "" {
		node.Licenses = []string{dt.packageJSON.License}
	}

	// Add homepage if available
	if dt.packageJSON.Homepage != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  dt.packageJSON.Homepage,
			Type: sbom.ExternalReference_WEBSITE,
		})
	}

	return node
}

// createNode creates a protobom Node for an npm package.
func (dt *DependencyTree) createNode(pkg *LockPackage) *sbom.Node {
	purl := buildPURL(pkg.Name, pkg.Version)

	node := &sbom.Node{
		Id:          uuid.NewString(),
		Type:        sbom.Node_PACKAGE,
		Name:        pkg.Name,
		Version:     pkg.Version,
		FileName:    pkg.Name,
		UrlDownload: pkg.Resolved,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl,
		},
		PrimaryPurpose: []sbom.Purpose{
			sbom.Purpose_LIBRARY,
		},
	}

	// Add integrity hash if available
	if pkg.Integrity != "" {
		algorithm, hash, err := ParseIntegrity(pkg.Integrity)
		if err == nil && hash != nil {
			hashAlgo := integrityAlgorithmToSBOM(algorithm)
			if hashAlgo != sbom.HashAlgorithm_UNKNOWN {
				node.Hashes = map[int32]string{
					int32(hashAlgo): hex.EncodeToString(hash),
				}
			}
		}
	}

	// Add license if available
	if pkg.License != "" {
		node.Licenses = []string{pkg.License}
	}

	return node
}

// buildPURL creates a PURL for an npm package.
func buildPURL(name, version string) string {
	// Handle scoped packages (@scope/name)
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			// Namespace is the scope without @
			namespace := url.PathEscape(parts[0][1:])
			pkgName := url.PathEscape(parts[1])
			return fmt.Sprintf("pkg:npm/%s/%s@%s", namespace, pkgName, version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", url.PathEscape(name), version)
}

// integrityAlgorithmToSBOM converts an SRI algorithm name to an sbom.HashAlgorithm.
func integrityAlgorithmToSBOM(algorithm string) sbom.HashAlgorithm {
	switch strings.ToLower(algorithm) {
	case "sha512":
		return sbom.HashAlgorithm_SHA512
	case "sha384":
		return sbom.HashAlgorithm_SHA384
	case "sha256":
		return sbom.HashAlgorithm_SHA256
	case "sha1":
		return sbom.HashAlgorithm_SHA1
	case "md5":
		return sbom.HashAlgorithm_MD5
	default:
		return sbom.HashAlgorithm_UNKNOWN
	}
}

// GetDependencyCount returns the total number of dependencies.
func (dt *DependencyTree) GetDependencyCount() int {
	// Subtract 1 for the root package
	count := len(dt.packageLock.Packages)
	if count > 0 {
		count--
	}
	return count
}

// GetDirectDependencyCount returns the number of direct dependencies.
func (dt *DependencyTree) GetDirectDependencyCount() int {
	return len(dt.directDeps)
}

// ListDependencies returns a sorted list of all dependencies for debugging/testing.
func (dt *DependencyTree) ListDependencies() []string {
	deps := make([]string, 0, len(dt.pkgByPath))
	for path, pkg := range dt.pkgByPath {
		if path != "" { // Skip root
			deps = append(deps, fmt.Sprintf("%s@%s", pkg.Name, pkg.Version))
		}
	}
	sort.Strings(deps)
	return deps
}

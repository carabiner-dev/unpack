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
	"github.com/carabiner-dev/unpack/license"
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

	// The workspace members are the project's own packages too, each a
	// root. Their nodes are made before anything is walked, so that a
	// member the root or another member depends on is found already made
	// and related as it is.
	members := dt.packageLock.WorkspaceMembers()
	for _, memberPath := range members {
		member, ok := dt.pkgByPath[memberPath]
		if !ok {
			continue
		}
		node := dt.createNode(member)
		node.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
		if opts.CommitHash != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): opts.CommitHash},
				Type:   sbom.ExternalReference_VCS,
			})
		}
		nl.AddRootNode(node)
		dt.nodeCache[memberPath] = node
	}

	// Build the dependency tree from the root's direct dependencies
	visited := make(map[string]bool)
	if err := dt.buildFromRoot(nl, rootNode, visited, opts); err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}

	// And from each member's.
	for _, memberPath := range members {
		if err := dt.buildFromMember(nl, memberPath, visited, opts); err != nil {
			return nil, fmt.Errorf("building dependency tree of %s: %w", memberPath, err)
		}
	}

	return nl, nil
}

// buildFromMember adds the direct dependencies of a workspace member, as
// its lock entry states them, each kind gated the way the root's are, and
// walks what they pull in.
func (dt *DependencyTree) buildFromMember(nl *sbom.NodeList, memberPath string, visited map[string]bool, opts *api.DecomposerOptions) error {
	member, ok := dt.pkgByPath[memberPath]
	if !ok {
		return nil
	}
	memberNode := dt.nodeCache[memberPath]
	visited[memberPath] = true

	// One type per name, the first of normal, dev, peer and optional it
	// is declared as, like the root's.
	types := map[string]DependencyType{}
	for _, section := range []struct {
		deps    map[string]string
		depType DependencyType
	}{
		{member.Dependencies, DepTypeNormal},
		{member.DevDependencies, DepTypeDev},
		{member.PeerDependencies, DepTypePeer},
		{member.OptionalDependencies, DepTypeOptional},
	} {
		for name := range section.deps {
			if _, declared := types[name]; !declared {
				types[name] = section.depType
			}
		}
	}

	names := make([]string, 0, len(types))
	for name := range types {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, depName := range names {
		depType := types[depName]
		if depType == DepTypeDev && !opts.IncludeDev {
			continue
		}
		if depType == DepTypeOptional && !opts.IncludeOptional {
			continue
		}

		depPath := dt.resolveDependencyPath(memberPath, depName)
		depPkg, ok := dt.pkgByPath[depPath]
		if depPath == "" || !ok || depPath == memberPath {
			continue
		}

		depNode, exists := dt.nodeCache[depPath]
		if !exists {
			depNode = dt.createNode(depPkg)
			dt.nodeCache[depPath] = depNode
		}
		if err := nl.RelateNodeAtID(depNode, memberNode.GetId(), dt.depTypeToEdgeType(depType)); err != nil {
			return fmt.Errorf("relating %s to %s: %w", depName, member.Name, err)
		}
		if !exists && !visited[depPath] {
			if err := dt.buildSubtree(nl, depPkg, depNode, depPath, visited); err != nil {
				return err
			}
		}
	}
	return nil
}

// buildFromRoot builds the dependency tree starting from direct dependencies.
func (dt *DependencyTree) buildFromRoot(nl *sbom.NodeList, rootNode *sbom.Node, visited map[string]bool, opts *api.DecomposerOptions) error {
	// Process direct dependencies from package.json
	for depName, depType := range dt.directDeps {
		// Filter by dependency type based on common options
		if depType == DepTypeDev && !opts.IncludeDev {
			continue
		}
		if depType == DepTypeOptional && !opts.IncludeOptional {
			continue
		}

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
	if pkg.Dependencies == nil && pkg.OptionalDependencies == nil && pkg.PeerDependencies == nil {
		return nil
	}

	// Collect all dependencies (regular + optional + peer) for processing.
	// A peer is a package this one needs and expects its host to bring:
	// npm installs it, at the host's level, and when the lock holds it
	// there this package depends on it like on any other. One that is not
	// installed, as an optional peer may not be, resolves to nothing below
	// and gets no edge.
	allDeps := make(map[string]sbom.Edge_Type, len(pkg.Dependencies)+len(pkg.OptionalDependencies)+len(pkg.PeerDependencies))
	for name := range pkg.PeerDependencies {
		allDeps[name] = sbom.Edge_dependsOn
	}
	for name := range pkg.Dependencies {
		allDeps[name] = sbom.Edge_dependsOn
	}
	for name := range pkg.OptionalDependencies {
		allDeps[name] = sbom.Edge_optionalDependency
	}

	// Sort dependency names for deterministic output
	depNames := make([]string, 0, len(allDeps))
	for name := range allDeps {
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
		if !ok || depPath == parentPath {
			continue
		}

		// Get or create node for this dependency
		depNode, exists := dt.nodeCache[depPath]
		if !exists {
			depNode = dt.createNode(depPkg)
			dt.nodeCache[depPath] = depNode
		}

		edgeType := allDeps[depName]
		if err := nl.RelateNodeAtID(depNode, parentNode.GetId(), edgeType); err != nil {
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

		if candidate, ok := dt.pkgByPath[candidatePath]; ok {
			// A link stands for a directory of the project, which has
			// the entry the dependency is really met by.
			if candidate.Link && candidate.Resolved != "" {
				if _, ok := dt.pkgByPath[candidate.Resolved]; ok {
					return candidate.Resolved
				}
			}
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

	// Add description if available
	if dt.packageJSON.Description != "" {
		node.Description = dt.packageJSON.Description
	}

	// Add license if available
	if dt.packageJSON.License != "" {
		node.Licenses = []string{license.Normalize(dt.packageJSON.License, "")}
	}

	// Add homepage if available
	if dt.packageJSON.Homepage != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  dt.packageJSON.Homepage,
			Type: sbom.ExternalReference_WEBSITE,
		})
	}

	// Add repository if available
	if dt.packageJSON.Repository != nil && dt.packageJSON.Repository.URL != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  dt.packageJSON.Repository.URL,
			Type: sbom.ExternalReference_VCS,
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
		node.Licenses = []string{license.Normalize(pkg.License, "")}
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

// SRI hash algorithm names as they appear in package-lock integrity fields.
const (
	algoSHA512 = "sha512"
	algoSHA256 = "sha256"
)

// integrityAlgorithmToSBOM converts an SRI algorithm name to an sbom.HashAlgorithm.
func integrityAlgorithmToSBOM(algorithm string) sbom.HashAlgorithm {
	switch strings.ToLower(algorithm) {
	case algoSHA512:
		return sbom.HashAlgorithm_SHA512
	case "sha384":
		return sbom.HashAlgorithm_SHA384
	case algoSHA256:
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

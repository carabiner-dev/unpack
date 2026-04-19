// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// ResolvedDependency represents a dependency after mediation.
type ResolvedDependency struct {
	Coordinate Coordinate
	Scope      string
	Optional   bool
	Licenses   []License
	Hashes     map[string]string // algo name -> hex digest (e.g. "SHA1" -> "abc123")
	Depth      int
}

// hashesForNode converts the string-keyed hashes to protobom hash algorithm keys.
func (rd *ResolvedDependency) hashesForNode() map[int32]string {
	m := make(map[int32]string, len(rd.Hashes))
	for algo, digest := range rd.Hashes {
		switch algo {
		case "SHA1":
			m[int32(sbom.HashAlgorithm_SHA1)] = digest
		case "SHA256":
			m[int32(sbom.HashAlgorithm_SHA256)] = digest
		case "SHA512":
			m[int32(sbom.HashAlgorithm_SHA512)] = digest
		}
	}
	return m
}

// DependencyTree builds the resolved dependency graph from a Maven POM.
type DependencyTree struct {
	rootPOM  *POM
	resolver *Resolver
	opts     *Options

	// Resolved dependencies keyed by "groupId:artifactId".
	// Maven uses nearest-definition-wins: the first version
	// encountered at the shallowest depth wins.
	resolved map[string]*ResolvedDependency

	// Adjacency list: parent coord string -> []child coord string
	edges map[string][]string

	// Managed dependencies from dependencyManagement, keyed by "groupId:artifactId"
	managed map[string]*Dependency
}

// queueEntry is a BFS queue item for dependency resolution.
type queueEntry struct {
	dep         Dependency
	parentCoord string
	depth       int
	parentScope string
	exclusions  []Exclusion // accumulated from all ancestors
}

// NewDependencyTree creates a new dependency tree builder.
func NewDependencyTree(rootPOM *POM, resolver *Resolver, opts *Options) *DependencyTree {
	dt := &DependencyTree{
		rootPOM:  rootPOM,
		resolver: resolver,
		opts:     opts,
		resolved: make(map[string]*ResolvedDependency),
		edges:    make(map[string][]string),
		managed:  make(map[string]*Dependency),
	}

	// Index dependencyManagement
	if rootPOM.DependencyManagement != nil {
		for i := range rootPOM.DependencyManagement.Dependencies {
			d := &rootPOM.DependencyManagement.Dependencies[i]
			dt.managed[d.Key()] = d
		}
	}

	return dt
}

// Build performs BFS dependency resolution and returns the resolved tree.
func (dt *DependencyTree) Build() error {
	rootCoord := Coordinate{
		GroupID:    dt.rootPOM.EffectiveGroupID(),
		ArtifactID: dt.rootPOM.ArtifactID,
		Version:    dt.rootPOM.EffectiveVersion(),
	}

	// Add root to resolved set
	dt.resolved[rootCoord.Key()] = &ResolvedDependency{
		Coordinate: rootCoord,
		Licenses:   dt.rootPOM.Licenses,
		Depth:      0,
	}

	// Initialize BFS queue with direct dependencies
	var queue []queueEntry
	for i := range dt.rootPOM.Dependencies {
		dep := dt.applyManagement(dt.rootPOM.Dependencies[i])
		queue = append(queue, queueEntry{
			dep:         dep,
			parentCoord: rootCoord.String(),
			depth:       1,
			parentScope: ScopeCompile,
		})
	}

	// BFS
	for len(queue) > 0 {
		entry := queue[0]
		queue = queue[1:]

		dep := entry.dep
		key := dep.Key()

		// Skip if already resolved (nearest definition wins)
		if _, exists := dt.resolved[key]; exists {
			continue
		}

		// Skip excluded dependencies
		if dt.isExcluded(dep.GroupID, dep.ArtifactID, entry.exclusions) {
			continue
		}

		// Determine effective scope
		effectiveScope := dep.EffectiveScope()
		if entry.depth > 1 {
			effectiveScope = scopeTransitivity(entry.parentScope, effectiveScope)
			if effectiveScope == "" {
				continue // non-transitive scope combination
			}
		}

		// Filter by scope options
		if !dt.shouldIncludeScope(effectiveScope) {
			continue
		}

		// Skip optional dependencies unless configured to include them
		if dep.IsOptional() && !dt.opts.IncludeOptional {
			continue
		}

		// Resolve version range if needed
		version := dep.Version
		if IsVersionRange(version) && dt.resolver != nil {
			resolved, err := dt.resolver.ResolveVersionRange(dep.GroupID, dep.ArtifactID, version)
			if err != nil {
				continue // skip unresolvable ranges
			}
			version = resolved
		}

		coord := Coordinate{
			GroupID:    dep.GroupID,
			ArtifactID: dep.ArtifactID,
			Version:    version,
			Type:       dep.EffectiveType(),
			Classifier: dep.Classifier,
			RepoURL:    dt.nonDefaultRepoURL(),
		}

		// Fetch the dependency's POM for license info and transitive deps
		var licenses []License
		var transitiveDeps []Dependency
		if dt.resolver != nil && version != "" {
			depPOM, err := dt.resolver.FetchPOM(dep.GroupID, dep.ArtifactID, version)
			if err == nil {
				// Try to resolve effective POM for accurate data
				effective, err := dt.resolver.ResolveEffectivePOM(depPOM)
				if err == nil {
					depPOM = effective
				}
				licenses = depPOM.Licenses

				// Apply the dep's own dependencyManagement to its dependencies
				// so that version-less deps get their versions filled in.
				depManaged := make(map[string]*Dependency)
				if depPOM.DependencyManagement != nil {
					for i := range depPOM.DependencyManagement.Dependencies {
						d := &depPOM.DependencyManagement.Dependencies[i]
						depManaged[d.Key()] = d
					}
				}
				for i := range depPOM.Dependencies {
					d := depPOM.Dependencies[i]
					if m, ok := depManaged[d.Key()]; ok {
						if d.Version == "" && m.Version != "" {
							d.Version = m.Version
						}
						if d.Scope == "" && m.Scope != "" {
							d.Scope = m.Scope
						}
						if len(d.Exclusions) == 0 && len(m.Exclusions) > 0 {
							d.Exclusions = m.Exclusions
						}
					}
					transitiveDeps = append(transitiveDeps, d)
				}
			}
		}

		// Add to resolved set
		dt.resolved[key] = &ResolvedDependency{
			Coordinate: coord,
			Scope:      effectiveScope,
			Optional:   dep.IsOptional(),
			Licenses:   licenses,
			Depth:      entry.depth,
		}

		// Record edge
		dt.edges[entry.parentCoord] = append(dt.edges[entry.parentCoord], coord.String())

		// Enqueue transitive dependencies
		// Accumulate exclusions from this dependency
		allExclusions := append(entry.exclusions, dep.Exclusions...) //nolint:gocritic

		for i := range transitiveDeps {
			tdep := dt.applyManagement(transitiveDeps[i])
			tScope := tdep.EffectiveScope()

			// Only compile and runtime deps are transitive
			if tScope != ScopeCompile && tScope != ScopeRuntime {
				continue
			}

			queue = append(queue, queueEntry{
				dep:         tdep,
				parentCoord: coord.String(),
				depth:       entry.depth + 1,
				parentScope: effectiveScope,
				exclusions:  allExclusions,
			})
		}
	}

	return nil
}

// applyManagement applies dependencyManagement overrides to a dependency.
func (dt *DependencyTree) applyManagement(dep Dependency) Dependency { //nolint:gocritic // returns modified copy
	managed, ok := dt.managed[dep.Key()]
	if !ok {
		return dep
	}

	if dep.Version == "" && managed.Version != "" {
		dep.Version = managed.Version
	}
	if dep.Scope == "" && managed.Scope != "" {
		dep.Scope = managed.Scope
	}
	if len(dep.Exclusions) == 0 && len(managed.Exclusions) > 0 {
		dep.Exclusions = managed.Exclusions
	}

	return dep
}

// isExcluded checks if a dependency is excluded by any accumulated exclusion.
func (dt *DependencyTree) isExcluded(groupID, artifactID string, exclusions []Exclusion) bool {
	for _, excl := range exclusions {
		if excl.Matches(groupID, artifactID) {
			return true
		}
	}
	return false
}

// shouldIncludeScope returns true if a dependency with the given scope should be included.
func (dt *DependencyTree) shouldIncludeScope(scope string) bool {
	switch scope {
	case ScopeCompile, ScopeRuntime:
		return true
	case ScopeTest:
		return dt.opts.IncludeTest
	case ScopeProvided:
		return dt.opts.IncludeProvided
	case ScopeSystem:
		return false
	default:
		return true
	}
}

// scopeTransitivity implements Maven's scope transitivity rules.
// Returns "" if the combination is non-transitive.
func scopeTransitivity(parentScope, depScope string) string {
	if depScope == ScopeProvided || depScope == ScopeTest {
		return "" // provided and test are never transitive
	}

	switch parentScope {
	case ScopeCompile:
		if depScope == ScopeCompile {
			return ScopeCompile
		}
		return ScopeRuntime
	case ScopeProvided:
		return ScopeProvided
	case ScopeRuntime:
		return ScopeRuntime
	case ScopeTest:
		return ScopeTest
	default:
		return depScope
	}
}

// FetchHashes fetches artifact checksums for all resolved dependencies
// in parallel and stores them in the resolved dependency entries.
func (dt *DependencyTree) FetchHashes() {
	if dt.resolver == nil {
		return
	}

	rootKey := dt.rootPOM.EffectiveGroupID() + ":" + dt.rootPOM.ArtifactID

	// Collect coordinates of all non-root resolved dependencies,
	// resolving SNAPSHOT versions to their timestamped filenames.
	coords := make([]Coordinate, 0, len(dt.resolved))
	for key, rd := range dt.resolved {
		if key == rootKey {
			continue
		}
		ext := rd.Coordinate.Type
		if ext == "" {
			ext = DefaultType
		}
		rd.Coordinate.SnapshotVersion = dt.resolver.ResolveSnapshotVersion(
			rd.Coordinate.GroupID, rd.Coordinate.ArtifactID,
			rd.Coordinate.Version, ext, rd.Coordinate.Classifier,
		)
		coords = append(coords, rd.Coordinate)
	}

	if len(coords) == 0 {
		return
	}

	// Fetch all checksum file hashes in parallel
	allHashes := dt.resolver.FetchAllArtifactHashes(coords)

	// If ModernHashes is enabled, download artifacts and compute SHA-256/SHA-512
	if dt.opts.ModernHashes {
		computed := dt.resolver.ComputeArtifactHashes(coords)
		for key, hashes := range computed {
			if existing, ok := allHashes[key]; ok {
				for algo, digest := range hashes {
					existing[algo] = digest
				}
			} else {
				allHashes[key] = hashes
			}
		}
	}

	// Store the hashes back on the resolved dependencies
	for _, rd := range dt.resolved {
		key := rd.Coordinate.GroupID + ":" + rd.Coordinate.ArtifactID + ":" + rd.Coordinate.Version
		if h, ok := allHashes[key]; ok {
			rd.Hashes = h
		}
	}
}

// ToNodeList converts the resolved dependency tree to a protobom NodeList.
func (dt *DependencyTree) ToNodeList(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()

	rootCoord := Coordinate{
		GroupID:    dt.rootPOM.EffectiveGroupID(),
		ArtifactID: dt.rootPOM.ArtifactID,
		Version:    dt.rootPOM.EffectiveVersion(),
	}

	// Use version from options if provided
	version := rootCoord.Version
	if opts != nil && opts.Version != "" {
		version = opts.Version
	}
	rootCoord.Version = version

	// Create root node
	rootNode := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    rootCoord.ArtifactID,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): rootCoord.PURL(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}

	// Add licenses from root POM, normalized to SPDX identifiers
	for _, lic := range dt.rootPOM.Licenses {
		rootNode.Licenses = append(rootNode.Licenses, NormalizeLicense(lic))
	}

	if opts != nil && opts.CommitHash != "" {
		rootNode.ExternalReferences = append(rootNode.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{
				int32(sbom.HashAlgorithm_SHA1): opts.CommitHash,
			},
			Type: sbom.ExternalReference_VCS,
		})
	}

	nl.AddRootNode(rootNode)

	// Create a map of coord string -> node for linking
	nodeMap := map[string]*sbom.Node{
		rootCoord.String(): rootNode,
	}

	// Create nodes for all resolved dependencies
	// Sort keys for deterministic output
	keys := make([]string, 0, len(dt.resolved))
	for k := range dt.resolved {
		if k == rootCoord.Key() {
			continue // skip root
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		rd := dt.resolved[key]
		node := dt.createDependencyNode(rd)
		nodeMap[rd.Coordinate.String()] = node
	}

	// Create edges
	for parentCoord, children := range dt.edges {
		parentNode, ok := nodeMap[parentCoord]
		if !ok {
			continue
		}

		for _, childCoord := range children {
			childNode, ok := nodeMap[childCoord]
			if !ok {
				continue
			}

			// Determine edge type based on the child's scope
			edgeType := dt.edgeTypeForCoord(childCoord)
			if err := nl.RelateNodeAtID(childNode, parentNode.GetId(), edgeType); err != nil {
				return nil, fmt.Errorf("relating %s to %s: %w", childCoord, parentCoord, err)
			}
		}
	}

	return nl, nil
}

// createDependencyNode creates a protobom Node for a resolved dependency.
func (dt *DependencyTree) createDependencyNode(rd *ResolvedDependency) *sbom.Node {
	groupPath := strings.ReplaceAll(rd.Coordinate.GroupID, ".", "/")
	downloadURL := fmt.Sprintf("%s/%s/%s/%s/%s",
		defaultRepoURL, groupPath,
		rd.Coordinate.ArtifactID, rd.Coordinate.Version,
		rd.Coordinate.ArtifactFilename(),
	)

	node := &sbom.Node{
		Id:          uuid.NewString(),
		Type:        sbom.Node_PACKAGE,
		Name:        rd.Coordinate.ArtifactID,
		Version:     rd.Coordinate.Version,
		UrlDownload: downloadURL,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): rd.Coordinate.PURL(),
		},
		Hashes: rd.hashesForNode(),
		PrimaryPurpose: []sbom.Purpose{
			sbom.Purpose_LIBRARY,
		},
	}

	for _, lic := range rd.Licenses {
		node.Licenses = append(node.Licenses, NormalizeLicense(lic))
	}

	return node
}

// nonDefaultRepoURL returns the resolver's repo URL if it differs from Maven Central,
// or empty string otherwise.
func (dt *DependencyTree) nonDefaultRepoURL() string {
	if dt.resolver != nil && dt.resolver.RepoURL != defaultRepoURL {
		return dt.resolver.RepoURL
	}
	return ""
}

// edgeTypeForCoord returns the appropriate edge type for a dependency.
func (dt *DependencyTree) edgeTypeForCoord(coordStr string) sbom.Edge_Type {
	// Find the resolved dependency by matching coord string
	for _, rd := range dt.resolved {
		if rd.Coordinate.String() == coordStr {
			if rd.Optional {
				return sbom.Edge_optionalDependency
			}
			switch rd.Scope {
			case ScopeTest:
				return sbom.Edge_devDependency
			default:
				return sbom.Edge_dependsOn
			}
		}
	}
	return sbom.Edge_dependsOn
}

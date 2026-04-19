// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"

	khttp "sigs.k8s.io/release-utils/http"
)

const (
	defaultRepoURL     = "https://repo1.maven.org/maven2"
	defaultConcurrency = 10
	defaultTimeout     = 30 * time.Second
	maxParentDepth     = 10
)

// Resolver fetches and caches Maven POMs from remote repositories.
type Resolver struct {
	Agent   *khttp.Agent
	RepoURL string
	cache   map[string]*POM
	mu      sync.RWMutex
}

// NewResolver creates a Resolver with the given options.
func NewResolver(opts *Options) *Resolver {
	repoURL := opts.RepoURL
	if repoURL == "" {
		repoURL = defaultRepoURL
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	agent := khttp.NewAgent().
		WithTimeout(defaultTimeout).
		WithMaxParallel(concurrency).
		WithFailOnHTTPError(true)

	return &Resolver{
		Agent:   agent,
		RepoURL: repoURL,
		cache:   make(map[string]*POM),
	}
}

// cacheKey returns the cache lookup key for a coordinate.
func cacheKey(groupID, artifactID, version string) string {
	return groupID + ":" + artifactID + ":" + version
}

// FetchPOM fetches a POM from the repository, parses it, and caches the result.
func (r *Resolver) FetchPOM(groupID, artifactID, version string) (*POM, error) {
	key := cacheKey(groupID, artifactID, version)

	r.mu.RLock()
	if pom, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return pom, nil
	}
	r.mu.RUnlock()

	url := r.pomURL(groupID, artifactID, version)
	data, err := r.Agent.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching POM %s: %w", key, err)
	}

	pom, err := ParsePomXMLData(data)
	if err != nil {
		return nil, fmt.Errorf("parsing POM %s: %w", key, err)
	}

	r.mu.Lock()
	r.cache[key] = pom
	r.mu.Unlock()

	return pom, nil
}

// pomURL constructs the Maven repository URL for a POM file.
func (r *Resolver) pomURL(groupID, artifactID, version string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", r.RepoURL, groupPath, artifactID, version, artifactID, version)
}

// metadataURL constructs the URL for maven-metadata.xml.
func (r *Resolver) metadataURL(groupID, artifactID string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	return fmt.Sprintf("%s/%s/%s/maven-metadata.xml", r.RepoURL, groupPath, artifactID)
}

// mavenMetadata represents the structure of maven-metadata.xml.
type mavenMetadata struct {
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Latest     string   `xml:"versioning>latest"`
	Release    string   `xml:"versioning>release"`
	Versions   []string `xml:"versioning>versions>version"`
}

// FetchAvailableVersions fetches maven-metadata.xml and returns all versions.
func (r *Resolver) FetchAvailableVersions(groupID, artifactID string) ([]string, error) {
	url := r.metadataURL(groupID, artifactID)
	data, err := r.Agent.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata for %s:%s: %w", groupID, artifactID, err)
	}

	var meta mavenMetadata
	if err := xml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing metadata for %s:%s: %w", groupID, artifactID, err)
	}

	return meta.Versions, nil
}

// artifactURL constructs the Maven repository URL for a JAR artifact.
func (r *Resolver) artifactURL(groupID, artifactID, version string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar", r.RepoURL, groupPath, artifactID, version, artifactID, version)
}

// hashSuffix pairs a file extension with its algorithm name.
type hashSuffix struct {
	suffix string
	algo   string
}

// supportedHashes lists the hash files we attempt to fetch from the repo.
var supportedHashes = []hashSuffix{
	{".sha1", "SHA1"},
	{".sha256", "SHA256"},
}

// FetchAllArtifactHashes fetches SHA-1 and SHA-256 checksums for multiple
// artifacts in parallel using the Agent's GetGroup. It returns a map keyed
// by "groupId:artifactId:version" containing algo->digest maps.
func (r *Resolver) FetchAllArtifactHashes(coords []Coordinate) map[string]map[string]string {
	if len(coords) == 0 {
		return nil
	}

	// Build the list of URLs to fetch: 2 per coordinate (sha1, sha256)
	urls := make([]string, 0, len(coords)*len(supportedHashes))
	for _, c := range coords {
		base := r.artifactURL(c.GroupID, c.ArtifactID, c.Version)
		for _, h := range supportedHashes {
			urls = append(urls, base+h.suffix)
		}
	}

	// Fetch all hash files in parallel
	bodies, errs := r.Agent.GetGroup(urls)

	// Parse results back into per-coordinate hash maps
	result := make(map[string]map[string]string, len(coords))
	for i, c := range coords {
		hashes := make(map[string]string)
		for j, h := range supportedHashes {
			idx := i*len(supportedHashes) + j
			if errs[idx] != nil || len(bodies[idx]) == 0 {
				continue
			}
			digest := strings.TrimSpace(string(bodies[idx]))
			// Some repos append the filename after the hash
			if sp := strings.IndexByte(digest, ' '); sp > 0 {
				digest = digest[:sp]
			}
			if digest != "" {
				hashes[h.algo] = digest
			}
		}
		if len(hashes) > 0 {
			result[cacheKey(c.GroupID, c.ArtifactID, c.Version)] = hashes
		}
	}

	return result
}

// ResolveVersionRange resolves a version range to a concrete version.
func (r *Resolver) ResolveVersionRange(groupID, artifactID, rangeSpec string) (string, error) {
	vr, err := ParseVersionRange(rangeSpec)
	if err != nil {
		return "", fmt.Errorf("parsing version range %q: %w", rangeSpec, err)
	}

	versions, err := r.FetchAvailableVersions(groupID, artifactID)
	if err != nil {
		return "", err
	}

	best := vr.SelectVersion(versions)
	if best == "" {
		return "", fmt.Errorf("no version of %s:%s satisfies range %s", groupID, artifactID, rangeSpec)
	}

	return best, nil
}

// ResolveEffectivePOM resolves the full parent chain, merges inherited data,
// processes BOM imports, and interpolates all properties.
func (r *Resolver) ResolveEffectivePOM(pom *POM) (*POM, error) {
	// Resolve parent chain
	resolved, err := r.resolveParentChain(pom, 0)
	if err != nil {
		return nil, fmt.Errorf("resolving parent chain: %w", err)
	}

	// Process BOM imports in dependencyManagement
	if err := r.resolveBOMImports(resolved, 0); err != nil {
		return nil, fmt.Errorf("resolving BOM imports: %w", err)
	}

	// Interpolate all properties
	InterpolatePOM(resolved)

	return resolved, nil
}

// resolveParentChain walks up the parent chain and merges each parent into the child.
func (r *Resolver) resolveParentChain(pom *POM, depth int) (*POM, error) {
	if depth > maxParentDepth {
		return nil, fmt.Errorf("parent chain exceeds maximum depth of %d", maxParentDepth)
	}

	if pom.Parent == nil {
		return pom, nil
	}

	parentPOM, err := r.FetchPOM(pom.Parent.GroupID, pom.Parent.ArtifactID, pom.Parent.Version)
	if err != nil {
		// Parent resolution failure is non-fatal: return what we have
		return pom, nil //nolint:nilerr
	}

	// Recursively resolve the parent's own parents first
	resolvedParent, err := r.resolveParentChain(parentPOM, depth+1)
	if err != nil {
		return pom, nil //nolint:nilerr
	}

	// Merge parent into child
	return MergeParent(pom, resolvedParent), nil
}

// MergeParent merges a parent POM into a child POM.
// Child values take precedence over parent values.
func MergeParent(child, parent *POM) *POM {
	// Inherit groupId and version if not set
	if child.GroupID == "" {
		child.GroupID = parent.GroupID
	}
	if child.Version == "" {
		child.Version = parent.Version
	}

	// Merge properties: parent first, child overrides
	merged := make(Properties)
	for k, v := range parent.Properties {
		merged[k] = v
	}
	for k, v := range child.Properties {
		merged[k] = v
	}
	child.Properties = merged

	// Merge dependencyManagement: child entries take precedence
	if parent.DependencyManagement != nil {
		if child.DependencyManagement == nil {
			child.DependencyManagement = &DependencyManagement{}
		}

		// Build lookup of child's managed deps
		childManaged := make(map[string]struct{})
		for i := range child.DependencyManagement.Dependencies {
			childManaged[child.DependencyManagement.Dependencies[i].Key()] = struct{}{}
		}

		// Add parent managed deps that child doesn't override
		for i := range parent.DependencyManagement.Dependencies {
			d := parent.DependencyManagement.Dependencies[i]
			if _, exists := childManaged[d.Key()]; !exists {
				child.DependencyManagement.Dependencies = append(
					child.DependencyManagement.Dependencies, d,
				)
			}
		}
	}

	// Inherit licenses if child has none
	if len(child.Licenses) == 0 {
		child.Licenses = parent.Licenses
	}

	// Inherit repositories
	if len(child.Repositories) == 0 {
		child.Repositories = parent.Repositories
	}

	return child
}

// resolveBOMImports processes dependencyManagement entries with
// scope=import and type=pom, merging their dependencyManagement
// into the current POM.
func (r *Resolver) resolveBOMImports(pom *POM, depth int) error {
	if depth > maxParentDepth {
		return fmt.Errorf("BOM import chain exceeds maximum depth of %d", maxParentDepth)
	}

	if pom.DependencyManagement == nil {
		return nil
	}

	// First interpolate so we can resolve BOM coordinates
	InterpolatePOM(pom)

	var remaining []Dependency
	var imported []Dependency

	for i := range pom.DependencyManagement.Dependencies {
		dep := pom.DependencyManagement.Dependencies[i]
		if dep.Scope == ScopeImport && dep.EffectiveType() == "pom" {
			bomPOM, err := r.FetchPOM(dep.GroupID, dep.ArtifactID, dep.Version)
			if err != nil {
				// Skip unresolvable BOMs
				continue
			}

			// Resolve the BOM's own parents and BOMs
			resolved, err := r.resolveParentChain(bomPOM, 0)
			if err != nil {
				continue
			}

			// Interpolate the BOM
			InterpolatePOM(resolved)

			// Recursively resolve nested BOM imports
			if err := r.resolveBOMImports(resolved, depth+1); err != nil {
				continue
			}

			if resolved.DependencyManagement != nil {
				imported = append(imported, resolved.DependencyManagement.Dependencies...)
			}
		} else {
			remaining = append(remaining, dep)
		}
	}

	// Build lookup of POM's own managed deps (non-import entries take precedence)
	ownManaged := make(map[string]struct{})
	for i := range remaining {
		ownManaged[remaining[i].Key()] = struct{}{}
	}

	// Add imported deps that don't conflict with own
	for i := range imported {
		d := imported[i]
		if _, exists := ownManaged[d.Key()]; !exists {
			remaining = append(remaining, d)
			ownManaged[d.Key()] = struct{}{}
		}
	}

	pom.DependencyManagement.Dependencies = remaining
	return nil
}

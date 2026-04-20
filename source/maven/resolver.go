// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/carabiner-dev/hasher"
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

// FetchPOM fetches a POM from the resolver's configured repository.
func (r *Resolver) FetchPOM(groupID, artifactID, version string) (*POM, error) {
	return r.FetchPOMFrom(groupID, artifactID, version, "")
}

// FetchPOMFrom fetches a POM from an explicit repository URL, falling back
// to the resolver's configured RepoURL when repoURL is empty.
func (r *Resolver) FetchPOMFrom(groupID, artifactID, version, repoURL string) (*POM, error) {
	key := cacheKey(groupID, artifactID, version)

	r.mu.RLock()
	if pom, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return pom, nil
	}
	r.mu.RUnlock()

	url := r.pomURLFrom(groupID, artifactID, version, repoURL)
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

// effectiveRepoURL returns override when non-empty (trimmed), else r.RepoURL.
func (r *Resolver) effectiveRepoURL(override string) string {
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	return r.RepoURL
}

// pomURL constructs the Maven repository URL for a POM file using the
// resolver's configured repository.
func (r *Resolver) pomURL(groupID, artifactID, version string) string {
	return r.pomURLFrom(groupID, artifactID, version, "")
}

// pomURLFrom constructs the POM URL against an explicit repository URL
// (falling back to the resolver's) and resolves SNAPSHOT filenames against
// that same repository.
func (r *Resolver) pomURLFrom(groupID, artifactID, version, repoURL string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	base := r.effectiveRepoURL(repoURL)
	fileVersion := r.ResolveSnapshotVersionFrom(groupID, artifactID, version, "pom", "", repoURL)
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", base, groupPath, artifactID, version, artifactID, fileVersion)
}

// metadataURL constructs the URL for maven-metadata.xml.
func (r *Resolver) metadataURL(groupID, artifactID string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	return fmt.Sprintf("%s/%s/%s/maven-metadata.xml", r.RepoURL, groupPath, artifactID)
}

// mavenMetadata represents the structure of the artifact-level maven-metadata.xml
// (lists all available versions).
type mavenMetadata struct {
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Latest     string   `xml:"versioning>latest"`
	Release    string   `xml:"versioning>release"`
	Versions   []string `xml:"versioning>versions>version"`
}

// snapshotMetadata represents the version-level maven-metadata.xml for SNAPSHOT versions.
// It contains the timestamp and build number needed to construct the actual artifact filename.
type snapshotMetadata struct {
	Timestamp   string                 `xml:"versioning>snapshot>timestamp"`
	BuildNumber string                 `xml:"versioning>snapshot>buildNumber"`
	Versions    []snapshotVersionEntry `xml:"versioning>snapshotVersions>snapshotVersion"`
}

// snapshotVersionEntry is a single entry in the snapshotVersions list.
type snapshotVersionEntry struct {
	Classifier string `xml:"classifier"`
	Extension  string `xml:"extension"`
	Value      string `xml:"value"`
}

// isSnapshot returns true if the version string ends with -SNAPSHOT.
func isSnapshot(version string) bool {
	return strings.HasSuffix(strings.ToUpper(version), "-SNAPSHOT")
}

// versionMetadataURLFrom constructs the version-level maven-metadata.xml URL
// against an explicit repository URL (falling back to the resolver's).
func (r *Resolver) versionMetadataURLFrom(groupID, artifactID, version, repoURL string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	base := r.effectiveRepoURL(repoURL)
	return fmt.Sprintf("%s/%s/%s/%s/maven-metadata.xml", base, groupPath, artifactID, version)
}

// ResolveSnapshotVersion resolves a SNAPSHOT version against the resolver's
// configured repository. See ResolveSnapshotVersionFrom for details.
func (r *Resolver) ResolveSnapshotVersion(groupID, artifactID, version, ext, classifier string) string {
	return r.ResolveSnapshotVersionFrom(groupID, artifactID, version, ext, classifier, "")
}

// ResolveSnapshotVersionFrom fetches the version-level maven-metadata.xml for a
// SNAPSHOT version from an explicit repository URL (or the resolver's default
// when empty) and returns the resolved timestamped version string
// (e.g. "1.0-20260418.130000-2") for the given extension and classifier.
// Returns the original version unchanged if the metadata cannot be fetched.
func (r *Resolver) ResolveSnapshotVersionFrom(groupID, artifactID, version, ext, classifier, repoURL string) string {
	if !isSnapshot(version) {
		return version
	}

	url := r.versionMetadataURLFrom(groupID, artifactID, version, repoURL)
	data, err := r.Agent.Get(url)
	if err != nil {
		return version
	}

	var meta snapshotMetadata
	if err := xml.Unmarshal(data, &meta); err != nil {
		return version
	}

	// Try to find a matching snapshotVersion entry
	for _, sv := range meta.Versions {
		if sv.Extension == ext && sv.Classifier == classifier {
			return sv.Value
		}
	}

	// Fallback: construct from timestamp and build number
	if meta.Timestamp != "" && meta.BuildNumber != "" {
		base := strings.TrimSuffix(version, "-SNAPSHOT")
		base = strings.TrimSuffix(base, "-snapshot")
		return fmt.Sprintf("%s-%s-%s", base, meta.Timestamp, meta.BuildNumber)
	}

	return version
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

// artifactURL constructs the Maven repository URL for an artifact.
// Uses the coordinate's RepoURL when set (e.g. a SNAPSHOT hosted in a
// project-declared repository), otherwise falls back to the resolver's.
func (r *Resolver) artifactURL(coord *Coordinate) string {
	groupPath := strings.ReplaceAll(coord.GroupID, ".", "/")
	base := r.effectiveRepoURL(coord.RepoURL)
	return fmt.Sprintf("%s/%s/%s/%s/%s", base, groupPath, coord.ArtifactID, coord.Version, coord.ArtifactFilename())
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
	for i := range coords {
		base := r.artifactURL(&coords[i])
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

// ComputeArtifactHashes downloads artifacts in parallel and computes
// SHA-256 and SHA-512 digests locally. It returns a map keyed by
// "groupId:artifactId:version" containing algo->hex digest maps.
func (r *Resolver) ComputeArtifactHashes(coords []Coordinate) map[string]map[string]string {
	if len(coords) == 0 {
		return nil
	}

	// Build artifact URLs
	urls := make([]string, len(coords))
	for i := range coords {
		urls[i] = r.artifactURL(&coords[i])
	}

	// Download all artifacts in parallel
	bodies, errs := r.Agent.GetGroup(urls)

	// Collect downloaded bodies and their coordinates for batch hashing
	var readers []io.Reader
	var coordIndices []int
	for i := range coords {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}
		readers = append(readers, bytes.NewReader(bodies[i]))
		coordIndices = append(coordIndices, i)
	}

	result := make(map[string]map[string]string, len(coords))
	if len(readers) == 0 {
		return result
	}

	h := hasher.New()
	hashResults, err := h.HashReaders(readers)
	if err != nil || hashResults == nil {
		return result
	}

	for j, idx := range coordIndices {
		c := coords[idx]
		hashes := make(map[string]string, len((*hashResults)[j]))
		for algo, digest := range (*hashResults)[j] {
			// Store with uppercase key to match hashesForNode expectations
			hashes[strings.ToUpper(string(algo))] = digest
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

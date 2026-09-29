// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbt

import (
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file turns a dependency snapshot into a graph. The root is the
// build: the repository at the commit the snapshot was taken. Under it,
// every manifest is a module the build defines, and under each module the
// tree sbt resolved for it: its direct dependencies, and from them the
// callers sbt recorded.
//
// Nodes are shared by purl across manifests. A library dozens of modules
// use is one node, and a module of the build that another depends on is
// the same node the manifest describes, which links the modules of the
// build into their real graph.

type snapshotBuilder struct {
	snapshot *Snapshot
	workDir  string
	opts     *api.DecomposerOptions

	nl    *sbom.NodeList
	nodes map[string]*sbom.Node
}

func newSnapshotBuilder(snapshot *Snapshot, workDir string, opts *api.DecomposerOptions) *snapshotBuilder {
	return &snapshotBuilder{
		snapshot: snapshot,
		workDir:  workDir,
		opts:     opts,
		nl:       sbom.NewNodeList(),
		nodes:    map[string]*sbom.Node{},
	}
}

func (sb *snapshotBuilder) build() (*sbom.NodeList, error) {
	root, err := sb.rootNode()
	if err != nil {
		return nil, err
	}
	sb.nl.AddRootNode(root)

	names := make([]string, 0, len(sb.snapshot.Manifests))
	for name := range sb.snapshot.Manifests {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		if err := sb.addManifest(root, name, sb.snapshot.Manifests[name]); err != nil {
			return nil, fmt.Errorf("manifest %s: %w", name, err)
		}
	}
	return sb.nl, nil
}

// addManifest relates a module of the build to the root and walks what it
// resolved.
func (sb *snapshotBuilder) addManifest(root *sbom.Node, key string, m *Manifest) error {
	name := m.Name
	if name == "" {
		name = key
	}
	module := sb.moduleNode(name)
	if err := sb.nl.RelateNodeAtID(module, root.GetId(), sbom.Edge_dependsOn); err != nil {
		return err
	}

	refs := make([]string, 0, len(m.Resolved))
	for ref := range m.Resolved {
		refs = append(refs, ref)
	}
	slices.Sort(refs)

	// Walk from the direct dependencies, following the callers sbt
	// recorded.
	visited := map[string]struct{}{}
	for _, ref := range refs {
		if m.Resolved[ref].Relationship != RelationshipDirect {
			continue
		}
		if err := sb.walk(m, ref, module, visited); err != nil {
			return err
		}
	}

	// A module can resolve something the walk never reaches: sbt lists
	// its callers by the modules that asked for it, and when those were
	// evicted in favor of another version, the edge is lost. It was still
	// resolved for the module, so it hangs from the module rather than
	// dropping out of the inventory.
	for _, ref := range refs {
		if _, ok := visited[ref]; ok || !sb.included(m.Resolved[ref]) {
			continue
		}
		slog.Debug("sbt: resolved module unreachable from direct dependencies", "manifest", name, "module", ref)
		if err := sb.walk(m, ref, module, visited); err != nil {
			return err
		}
	}
	return nil
}

// walk relates a resolved module to its parent and, the first time it is
// seen in this manifest, walks into its dependencies.
func (sb *snapshotBuilder) walk(m *Manifest, ref string, parent *sbom.Node, visited map[string]struct{}) error {
	dep, ok := m.Resolved[ref]
	if !ok {
		// Callers can name modules the manifest does not list: evicted
		// versions and the configurations left out of the snapshot.
		return nil
	}
	if !sb.included(dep) {
		return nil
	}

	node := sb.dependencyNode(ref, dep)
	if node.GetId() == parent.GetId() {
		return nil
	}
	if err := sb.nl.RelateNodeAtID(node, parent.GetId(), edgeType(dep)); err != nil {
		return err
	}

	if _, seen := visited[ref]; seen {
		return nil
	}
	visited[ref] = struct{}{}

	for _, child := range dep.Dependencies {
		if err := sb.walk(m, child, node, visited); err != nil {
			return err
		}
	}
	return nil
}

// included reports whether a resolved module makes it into the graph:
// development modules only do when asked for.
func (sb *snapshotBuilder) included(dep *DependencyNode) bool {
	return dep.Scope != ScopeDevelopment || sb.opts.IncludeDev
}

func edgeType(dep *DependencyNode) sbom.Edge_Type {
	if dep.Scope == ScopeDevelopment {
		return sbom.Edge_devDependency
	}
	return sbom.Edge_dependsOn
}

// dependencyNode returns the node of a resolved module, creating it the
// first time its purl is seen.
func (sb *snapshotBuilder) dependencyNode(ref string, dep *DependencyNode) *sbom.Node {
	if dep.PackageURL == "" {
		// Without a purl there is nothing to share the node by: the sbt
		// reference is the identity.
		return sb.node(ref, func() *sbom.Node {
			return &sbom.Node{
				Id:             uuid.NewString(),
				Type:           sbom.Node_PACKAGE,
				Name:           ref,
				PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
			}
		})
	}
	return sb.node(dep.PackageURL, func() *sbom.Node {
		return purlNode(dep.PackageURL, ref)
	})
}

// moduleNode returns the node of a module of the build. The manifest is
// named after the module (organization:name:revision), which spells the
// same purl a module depending on it resolves.
func (sb *snapshotBuilder) moduleNode(name string) *sbom.Node {
	org, artifact, version, ok := parseModuleRef(name)
	if !ok {
		return sb.node(name, func() *sbom.Node {
			return &sbom.Node{
				Id:             uuid.NewString(),
				Type:           sbom.Node_PACKAGE,
				Name:           name,
				PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
			}
		})
	}
	// Built the way sbt-dependency-submission spells them, so that the
	// strings match the purls of the resolved modules.
	p := fmt.Sprintf("pkg:maven/%s/%s@%s", org, artifact, version)
	return sb.node(p, func() *sbom.Node { return purlNode(p, name) })
}

func (sb *snapshotBuilder) node(key string, create func() *sbom.Node) *sbom.Node {
	if n, ok := sb.nodes[key]; ok {
		return n
	}
	n := create()
	sb.nodes[key] = n
	sb.nl.AddNode(n)
	return n
}

// purlNode builds a package node from its purl. The name is the maven
// artifact, as the maven decomposer names them; the group travels in the
// purl.
func purlNode(p, fallbackName string) *sbom.Node {
	node := &sbom.Node{
		Id:   uuid.NewString(),
		Type: sbom.Node_PACKAGE,
		Name: fallbackName,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): p,
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	if parsed, err := purl.FromString(p); err == nil {
		node.Name = parsed.Name
		node.Version = parsed.Version
	}
	return node
}

// parseModuleRef splits an sbt module reference, organization:name:revision.
func parseModuleRef(ref string) (org, name, version string, ok bool) {
	parts := strings.Split(ref, ":")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// rootNode builds the node of the build itself: the repository at the
// commit the snapshot was taken.
//
// The version and commit come from the checkout when unpack reads them
// from git, and from the snapshot otherwise. When both know the commit
// they have to agree: a snapshot of another commit describes another
// build.
func (sb *snapshotBuilder) rootNode() (*sbom.Node, error) {
	commit := sb.opts.CommitHash
	if sb.snapshot.Sha != "" {
		if commit != "" && !strings.EqualFold(commit, sb.snapshot.Sha) {
			return nil, fmt.Errorf(
				"dependency snapshot was taken at commit %s but the codebase is at %s",
				sb.snapshot.Sha, commit,
			)
		}
		commit = sb.snapshot.Sha
	}

	version := sb.opts.Version
	if version == "" {
		version = strings.TrimPrefix(sb.snapshot.Ref, "refs/tags/")
		if version == sb.snapshot.Ref {
			version = ""
		}
	}

	owner, repo := sb.snapshot.githubRepository()

	name := repo
	if name == "" {
		abs, err := filepath.Abs(sb.workDir)
		if err != nil {
			abs = sb.workDir
		}
		name = filepath.Base(abs)
	}

	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           name,
		Version:        version,
		Identifiers:    map[int32]string{},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}

	var p *purl.PackageURL
	if owner != "" {
		p = purl.NewPackageURL(purl.TypeGithub, owner, repo, version, nil, "")
	} else {
		p = purl.NewPackageURL(purl.TypeGeneric, "", name, version, nil, "")
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = p.ToString()

	if commit != "" {
		ref := &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): commit},
			Type:   sbom.ExternalReference_VCS,
		}
		// The commit goes in the locator too: not every format keeps
		// the hashes of a reference, SPDX 3 drops them.
		if owner != "" {
			ref.Url = fmt.Sprintf("git+https://github.com/%s/%s@%s", owner, repo, commit)
		}
		node.ExternalReferences = append(node.ExternalReferences, ref)
	}
	return node, nil
}

// githubRepository returns the repository the snapshot was generated in,
// read from the run URL of its job. It is only known for github.com:
// runs elsewhere, or snapshots made outside a workflow, return nothing.
func (s *Snapshot) githubRepository() (owner, repo string) {
	if s.Job == nil || s.Job.HTMLURL == "" {
		return "", ""
	}
	u, err := url.Parse(s.Job.HTMLURL)
	if err != nil || u.Host != "github.com" {
		return "", ""
	}
	// /{owner}/{repo}/actions/runs/{id}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}

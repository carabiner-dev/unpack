// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file turns a lockfile into the dependency graph one concrete
// environment sees. The lock resolves every environment at once; the tree
// builder walks it from the project's own packages, keeping the edges whose
// markers hold in the target environment and the fork of each package the
// edges point at, so one package ends up at one version.

// treeBuilder carries what one build needs.
type treeBuilder struct {
	lock *Lockfile
	env  *Environment
	opts *api.DecomposerOptions

	nl *sbom.NodeList

	// nodes indexes the nodes already built by package identity, which in a
	// forked lock is the name and the version together.
	nodes map[packageKey]*sbom.Node
	// walked guards the recursion: extras may point back at their package.
	walked map[packageKey]bool
	// enrichable marks the packages that came from the registry, which are
	// the only ones the index can be asked about: not the project's own,
	// and not the git, path and url dependencies, whose installed content
	// the index does not describe.
	enrichable map[packageKey]bool
}

type packageKey struct {
	name, version string
}

func newTreeBuilder(lock *Lockfile, env *Environment, opts *api.DecomposerOptions) *treeBuilder {
	return &treeBuilder{
		lock:       lock,
		env:        env,
		opts:       opts,
		nl:         sbom.NewNodeList(),
		nodes:      map[packageKey]*sbom.Node{},
		walked:     map[packageKey]bool{},
		enrichable: map[packageKey]bool{},
	}
}

// build walks the lock and returns the graph.
func (tb *treeBuilder) build() (*sbom.NodeList, error) {
	roots := []*Package{}
	for i := range tb.lock.Packages {
		pkg := &tb.lock.Packages[i]
		if pkg.Source.IsProject() && tb.applies(pkg) {
			roots = append(roots, pkg)
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no project package in the lockfile")
	}

	for _, root := range roots {
		if err := tb.addRoot(root); err != nil {
			return nil, err
		}
	}
	return tb.nl, nil
}

// addRoot builds the project's own node and everything reachable from it.
func (tb *treeBuilder) addRoot(root *Package) error {
	node := tb.createNode(root)
	node.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}

	// The caller may know the project's version and commit better than the
	// lock does: a lockfile version is whatever pyproject.toml said last.
	if tb.opts.Version != "" {
		node.Version = tb.opts.Version
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purl(root.Name, tb.opts.Version)
	}
	if tb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): tb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}

	tb.nl.AddRootNode(node)
	tb.nodes[keyOf(root)] = node
	tb.walked[keyOf(root)] = true

	if err := tb.walkDependencies(root, node, sbom.Edge_dependsOn); err != nil {
		return err
	}

	// The root's extras and dependency groups, when asked for. Sorted so
	// the graph comes out the same every run.
	if tb.opts.IncludeOptional {
		for _, extra := range sortedKeys(root.OptionalDependencies) {
			if err := tb.walkEdges(root.OptionalDependencies[extra], node, sbom.Edge_optionalDependency); err != nil {
				return err
			}
		}
	}
	if tb.opts.IncludeDev {
		for _, group := range sortedKeys(root.DevDependencies) {
			if err := tb.walkEdges(root.DevDependencies[group], node, sbom.Edge_devDependency); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkDependencies adds the package's runtime dependencies under its node.
func (tb *treeBuilder) walkDependencies(pkg *Package, node *sbom.Node, edgeType sbom.Edge_Type) error {
	return tb.walkEdges(pkg.Dependencies, node, edgeType)
}

// walkEdges adds an edge per dependency that holds in the environment, and
// recurses into targets not walked yet.
func (tb *treeBuilder) walkEdges(deps []Dependency, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	for i := range deps {
		dep := &deps[i]

		holds, err := tb.env.Evaluate(dep.Marker)
		if err != nil {
			return fmt.Errorf("evaluating marker on the edge to %s: %w", dep.Name, err)
		}
		if !holds {
			continue
		}

		target, err := tb.resolve(dep)
		if err != nil {
			return err
		}

		node, known := tb.nodes[keyOf(target)]
		if !known {
			node = tb.createNode(target)
			tb.nodes[keyOf(target)] = node
			tb.nl.AddNode(node)
		}
		if err := tb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
			return fmt.Errorf("relating %s to %s: %w", target.Name, parent.GetName(), err)
		}

		if !tb.walked[keyOf(target)] {
			tb.walked[keyOf(target)] = true
			if err := tb.walkDependencies(target, node, sbom.Edge_dependsOn); err != nil {
				return err
			}
		}

		// An edge naming extras pulls in the target's optional
		// dependencies for those extras: requests[socks] brings pysocks.
		for _, extra := range dep.Extra {
			if err := tb.walkEdges(target.OptionalDependencies[extra], node, sbom.Edge_optionalDependency); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolve finds the package an edge points at. In a forked lock the same
// name holds several entries; the edge's version narrows them, and the
// package's own resolution markers settle whatever remains.
func (tb *treeBuilder) resolve(dep *Dependency) (*Package, error) {
	var fallback *Package
	for i := range tb.lock.Packages {
		pkg := &tb.lock.Packages[i]
		if pkg.Name != dep.Name {
			continue
		}
		if dep.Version != "" && pkg.Version != dep.Version {
			continue
		}
		if tb.applies(pkg) {
			return pkg, nil
		}
		if fallback == nil {
			fallback = pkg
		}
	}

	// An entry whose resolution markers do not hold can still be the only
	// one the edge points at: an edge kept by its own marker knows better
	// than the coarser package-level split.
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("the lockfile has no package for the dependency on %s %s", dep.Name, dep.Version)
}

// applies says whether a package entry claims the target environment: it
// carries no resolution markers, or one of them holds.
func (tb *treeBuilder) applies(pkg *Package) bool {
	if len(pkg.ResolutionMarkers) == 0 {
		return true
	}
	for _, marker := range pkg.ResolutionMarkers {
		holds, err := tb.env.Evaluate(marker)
		if err == nil && holds {
			return true
		}
	}
	return false
}

// createNode builds the protobom node for a locked package, hashed with the
// artifact the environment would install.
func (tb *treeBuilder) createNode(pkg *Package) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    pkg.Name,
		Version: pkg.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl(pkg.Name, pkg.Version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}

	switch {
	case pkg.Source.Registry != "":
		tb.enrichable[keyOf(pkg)] = true
		if artifact := selectArtifact(pkg, tb.env); artifact != nil {
			node.UrlDownload = artifact.URL
			if algorithm, value := artifact.HashValue(); algorithm == "sha256" {
				node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): value}
			}
		}
	case pkg.Source.Git != "":
		// A git dependency has no artifacts to hash, but it knows exactly
		// where it comes from: uv records the resolved commit in the
		// source's fragment.
		node.UrlDownload = pkg.Source.Git
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  pkg.Source.Git,
			Type: sbom.ExternalReference_VCS,
		})
	case pkg.Source.URL != "":
		node.UrlDownload = pkg.Source.URL
	}
	// Path, directory and the project's own packages point at local
	// content, which has no address worth writing.
	return node
}

// purl names a PyPI package. The name is already normalized, which is the
// form the purl spec requires for pypi.
func purl(name, version string) string {
	return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
}

func keyOf(pkg *Package) packageKey {
	return packageKey{name: pkg.Name, version: pkg.Version}
}

func sortedKeys(m map[string][]Dependency) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file turns a poetry.lock and its manifest into the graph one
// concrete environment sees. The shape differs from the uv walk in what
// each file knows: the lock has no root and no direct edges, so the walk
// starts from the manifest's declarations, and group membership is not
// trusted from the lock — a 2.0 lock does not record it — but derived by
// walking each group from its own directs.

type poetryBuilder struct {
	lock     *PoetryLockfile
	manifest *PyProject
	env      *Environment
	opts     *api.DecomposerOptions

	nl         *sbom.NodeList
	nodes      map[packageKey]*sbom.Node
	walked     map[packageKey]bool
	enrichable map[packageKey]bool

	// group is the dependency group being walked: package-level markers in
	// a 2.1 lock are stated per group.
	group string
}

func newPoetryBuilder(lock *PoetryLockfile, manifest *PyProject, env *Environment, opts *api.DecomposerOptions) *poetryBuilder {
	return &poetryBuilder{
		lock:       lock,
		manifest:   manifest,
		env:        env,
		opts:       opts,
		nl:         sbom.NewNodeList(),
		nodes:      map[packageKey]*sbom.Node{},
		walked:     map[packageKey]bool{},
		enrichable: map[packageKey]bool{},
	}
}

// build walks the lock from the manifest's declarations.
func (pb *poetryBuilder) build() (*sbom.NodeList, error) {
	root, err := pb.addRoot()
	if err != nil {
		return nil, err
	}

	// The runtime dependencies.
	main, err := pb.manifest.MainDependencies()
	if err != nil {
		return nil, err
	}
	pb.group = "main"
	if err := pb.walkRequirements(main, root, sbom.Edge_dependsOn); err != nil {
		return nil, err
	}

	// The extras, when asked for. The environment's extras were enabled
	// before any walk, so packages whose lock markers test extra
	// membership resolve consistently everywhere.
	if pb.opts.IncludeOptional {
		extras, err := pb.manifest.ExtraDependencies()
		if err != nil {
			return nil, err
		}
		for _, extra := range sortedGroupNames(extras) {
			if err := pb.walkRequirements(extras[extra], root, sbom.Edge_optionalDependency); err != nil {
				return nil, err
			}
		}
	}

	// The dependency groups, when asked for, each walked from its own
	// directs: this is what derives membership on a 2.0 lock, and matches
	// the 2.1 group stamps without trusting them.
	if pb.opts.IncludeDev {
		groups, err := pb.manifest.GroupDependencies()
		if err != nil {
			return nil, err
		}
		for _, group := range sortedGroupNames(groups) {
			pb.group = group
			if err := pb.walkRequirements(groups[group], root, sbom.Edge_devDependency); err != nil {
				return nil, err
			}
		}
	}
	return pb.nl, nil
}

// addRoot builds the project's own node from the manifest.
func (pb *poetryBuilder) addRoot() (*sbom.Node, error) {
	name := pb.manifest.RootName()
	if name == "" {
		return nil, fmt.Errorf("pyproject.toml names no project")
	}
	version := pb.manifest.RootVersion()
	if pb.opts.Version != "" {
		version = pb.opts.Version
	}

	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl(name, version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	if pb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): pb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	pb.nl.AddRootNode(node)
	return node, nil
}

// walkRequirements adds an edge per declared requirement that holds in the
// environment, and recurses into the lock.
func (pb *poetryBuilder) walkRequirements(reqs []*requirement, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	for _, req := range reqs {
		holds, err := pb.env.Evaluate(req.Marker)
		if err != nil {
			return fmt.Errorf("evaluating marker on the edge to %s: %w", req.Name, err)
		}
		if !holds {
			continue
		}
		if err := pb.addEdge(req.Name, req.Extras, parent, edgeType); err != nil {
			return err
		}
	}
	return nil
}

// addEdge resolves a target in the lock, relates it, and walks on.
func (pb *poetryBuilder) addEdge(name string, extras []string, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	target := pb.resolve(name)
	if target == nil {
		// The lock has no applicable entry: the requirement's own marker
		// held but the package is for other environments (a 2.1 lock says
		// so per package), or it was declared and never locked. Either
		// way there is nothing to point at.
		return nil
	}

	node, known := pb.nodes[poetryKeyOf(target)]
	if !known {
		node = pb.createNode(target)
		pb.nodes[poetryKeyOf(target)] = node
		pb.nl.AddNode(node)
	}
	if err := pb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
		return fmt.Errorf("relating %s to %s: %w", name, parent.GetName(), err)
	}

	if !pb.walked[poetryKeyOf(target)] {
		pb.walked[poetryKeyOf(target)] = true
		for _, dep := range target.Dependencies {
			holds, err := pb.env.Evaluate(dep.Marker)
			if err != nil {
				return fmt.Errorf("evaluating marker on the edge to %s: %w", dep.Name, err)
			}
			if !holds {
				continue
			}
			if err := pb.addEdge(dep.Name, dep.Extras, node, sbom.Edge_dependsOn); err != nil {
				return err
			}
		}
	}

	// An edge naming extras pulls the extras' requirements in under the
	// target, as declared in the target's extras table.
	for _, extra := range extras {
		for _, line := range target.Extras[extra] {
			req, err := parseRequirement(line)
			if err != nil {
				return fmt.Errorf("extra %s of %s: %w", extra, name, err)
			}
			holds, err := pb.env.Evaluate(req.Marker)
			if err != nil || !holds {
				continue
			}
			if err := pb.addEdge(req.Name, req.Extras, node, sbom.Edge_optionalDependency); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolve finds the lock entry a name points at: the one whose markers, for
// the group being walked, hold in the environment. Names almost always hold
// one entry; a few hold several with disjoint markers.
func (pb *poetryBuilder) resolve(name string) *PoetryPackage {
	var fallback *PoetryPackage
	for i := range pb.lock.Packages {
		pkg := &pb.lock.Packages[i]
		if pkg.Name != name {
			continue
		}
		if pb.applies(pkg) {
			return pkg
		}
		if fallback == nil {
			fallback = pkg
		}
	}
	if fallback != nil && pb.singleEntry(name) {
		// The only entry of its name: an edge that survived its own marker
		// knows better than the package-level split.
		return fallback
	}
	return nil
}

func (pb *poetryBuilder) singleEntry(name string) bool {
	count := 0
	for i := range pb.lock.Packages {
		if pb.lock.Packages[i].Name == name {
			count++
		}
	}
	return count == 1
}

// applies says whether a lock entry claims the environment, judged by the
// marker for the group being walked.
func (pb *poetryBuilder) applies(pkg *PoetryPackage) bool {
	if len(pkg.Markers) == 0 {
		return true
	}
	marker, ok := pkg.Markers[pb.group]
	if !ok {
		marker, ok = pkg.Markers[""]
	}
	if !ok {
		// The package states markers, but none for this group: it serves
		// other groups' environments.
		return false
	}
	holds, err := pb.env.Evaluate(marker)
	return err == nil && holds
}

// createNode builds the protobom node for a locked package.
func (pb *poetryBuilder) createNode(pkg *PoetryPackage) *sbom.Node {
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
	if pkg.Description != "" {
		node.Description = pkg.Description
	}

	switch {
	case pkg.Source == nil:
		// From the default index: enrichable, and hashed with the artifact
		// the environment would install. The lock names artifacts by
		// filename only, so there is no download URL to record.
		pb.enrichable[poetryKeyOf(pkg)] = true
		pb.setArtifactHash(node, pkg)
	case pkg.Source.Type == "legacy":
		// An alternate index: hashed like the default one, but not asked
		// about on PyPI, which is not where it came from.
		pb.setArtifactHash(node, pkg)
	case pkg.Source.Type == "git":
		url := pkg.Source.URL
		if pkg.Source.ResolvedReference != "" {
			url += "#" + pkg.Source.ResolvedReference
		}
		node.UrlDownload = url
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  url,
			Type: sbom.ExternalReference_VCS,
		})
	case pkg.Source.Type == "url":
		node.UrlDownload = pkg.Source.URL
	}
	return node
}

// setArtifactHash hashes the node with the artifact the environment would
// install.
func (pb *poetryBuilder) setArtifactHash(node *sbom.Node, pkg *PoetryPackage) {
	file := selectPoetryArtifact(pkg.Files, pb.env)
	if file == nil {
		return
	}
	if algorithm, value := file.HashValue(); algorithm == hashSHA256 {
		node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): value}
	}
}

// selectPoetryArtifact picks the artifact the environment would install
// from the lock's file list: the best wheel by its filename tags, the sdist
// when none fits.
func selectPoetryArtifact(files []PoetryFile, env *Environment) *PoetryFile {
	best := (*PoetryFile)(nil)
	bestScore := -1
	var sdist *PoetryFile
	for i := range files {
		file := &files[i]
		if !strings.HasSuffix(file.File, ".whl") {
			if sdist == nil {
				sdist = file
			}
			continue
		}
		if score, ok := wheelScore(file.File, env); ok && score > bestScore {
			best, bestScore = file, score
		}
	}
	if best != nil {
		return best
	}
	return sdist
}

func poetryKeyOf(pkg *PoetryPackage) packageKey {
	return packageKey{name: pkg.Name, version: pkg.Version}
}

func sortedGroupNames[T any](m map[string]T) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

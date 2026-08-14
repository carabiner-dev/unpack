// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"gopkg.in/yaml.v3"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/license"
)

// This file reads yarn.lock in the berry (v2+) format: YAML, one entry per
// resolution, keyed by protocol-carrying selectors — "debug@npm:^4.3.4",
// "liba@workspace:*". The workspaces are entries of the lock itself, their
// dependencies flattened with the dev ones mixed in and unmarked, so the
// kinds come from each workspace's package.json, by name.
//
// Berry's checksum field hashes yarn's own cache archive, not the registry
// tarball, so nodes deliberately carry no hashes: a hash nothing else can
// reproduce identifies nothing.

// YarnBerryLock is a parsed berry yarn.lock.
type YarnBerryLock struct {
	// Entries maps every selector to its resolution, edges resolving by
	// exact lookup as in the classic format.
	Entries map[string]*BerryPackage

	// Workspaces are the project's own packages, keyed by their directory.
	Workspaces map[string]*BerryPackage
}

// BerryPackage is one resolved entry.
type BerryPackage struct {
	Name    string
	Version string

	// WorkspacePath is the directory of a workspace entry, empty for a
	// fetched package.
	WorkspacePath string

	// Dependencies maps names to the protocol-carrying references the
	// entry requires.
	Dependencies map[string]string
}

// rawBerryEntry is one YAML entry as written.
type rawBerryEntry struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
}

// ParseYarnBerryLock reads a berry yarn.lock document.
func ParseYarnBerryLock(data []byte) (*YarnBerryLock, error) {
	raw := map[string]rawBerryEntry{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing yarn.lock (berry): %w", err)
	}

	lock := &YarnBerryLock{
		Entries:    map[string]*BerryPackage{},
		Workspaces: map[string]*BerryPackage{},
	}

	for key, entry := range raw {
		if key == "__metadata" {
			continue
		}

		name, err := yarnSelectorName(entry.Resolution)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", key, err)
		}
		pkg := &BerryPackage{
			Name:         name,
			Version:      entry.Version,
			Dependencies: entry.Dependencies,
		}

		// A workspace resolution names its directory rather than a
		// version: "liba@workspace:packages/liba".
		if _, wsPath, isWS := strings.Cut(entry.Resolution, "@workspace:"); isWS {
			pkg.WorkspacePath = path.Clean(wsPath)
			lock.Workspaces[pkg.WorkspacePath] = pkg
		}

		// Every selector of the key resolves to this entry.
		for _, selector := range strings.Split(key, ",") {
			lock.Entries[strings.TrimSpace(selector)] = pkg
		}
	}

	if len(lock.Workspaces) == 0 {
		return nil, fmt.Errorf("yarn.lock (berry) holds no workspace entry")
	}
	return lock, nil
}

// buildYarnBerryTree turns a berry lock into the graph. Every workspace
// roots it with the identity its own package.json states — the lock says
// 0.0.0-use.local — and classifies its direct dependencies, which the lock
// flattened together.
func buildYarnBerryTree(lock *YarnBerryLock, workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	bb := &berryBuilder{
		lock:  lock,
		opts:  opts,
		nl:    sbom.NewNodeList(),
		nodes: map[*BerryPackage]*sbom.Node{},
	}

	paths := make([]string, 0, len(lock.Workspaces))
	for wsPath := range lock.Workspaces {
		paths = append(paths, wsPath)
	}
	sort.Strings(paths)

	// Roots first, so workspace cross-dependencies resolve to nodes that
	// exist whichever way they point.
	manifests := map[string]*PackageJSON{}
	for _, wsPath := range paths {
		manifest, err := ParsePackageJSON(filepath.Join(workDir, filepath.FromSlash(wsPath)))
		if err != nil {
			return nil, fmt.Errorf("workspace %s: %w", wsPath, err)
		}
		manifests[wsPath] = manifest

		ws := lock.Workspaces[wsPath]
		node := bb.workspaceNode(ws, manifest)
		bb.nodes[ws] = node
		bb.nl.AddRootNode(node)
	}

	for _, wsPath := range paths {
		ws := lock.Workspaces[wsPath]
		if err := bb.workspaceEdges(ws, manifests[wsPath]); err != nil {
			return nil, err
		}
	}
	return bb.nl, nil
}

type berryBuilder struct {
	lock *YarnBerryLock
	opts *api.DecomposerOptions

	nl    *sbom.NodeList
	nodes map[*BerryPackage]*sbom.Node
}

// workspaceNode builds a workspace's root node from its manifest.
func (bb *berryBuilder) workspaceNode(ws *BerryPackage, manifest *PackageJSON) *sbom.Node {
	name := manifest.Name
	if name == "" {
		name = ws.Name
	}
	version := manifest.Version
	if bb.opts.Version != "" {
		version = bb.opts.Version
	}

	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): buildPURL(name, version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	if manifest.License != "" {
		node.Licenses = []string{license.Normalize(manifest.License, "")}
	}
	if bb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): bb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

// workspaceEdges walks a workspace's flattened dependency table, telling
// the kinds apart by the manifest's sections and gating them accordingly.
func (bb *berryBuilder) workspaceEdges(ws *BerryPackage, manifest *PackageJSON) error {
	parent := bb.nodes[ws]
	for _, name := range sortedDepNames(ws.Dependencies) {
		edgeType := sbom.Edge_dependsOn
		switch {
		case manifest.Dependencies[name] != "":
		case manifest.DevDependencies[name] != "":
			if !bb.opts.IncludeDev {
				continue
			}
			edgeType = sbom.Edge_devDependency
		case manifest.OptionalDependencies[name] != "":
			if !bb.opts.IncludeOptional {
				continue
			}
			edgeType = sbom.Edge_optionalDependency
		}
		if err := bb.addEdge(name, ws.Dependencies[name], parent, edgeType); err != nil {
			return err
		}
	}
	return nil
}

// addEdge resolves a reference through the lock's selectors, relates it,
// and walks into it when it is new.
func (bb *berryBuilder) addEdge(name, ref string, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	pkg, ok := bb.lock.Entries[name+"@"+ref]
	if !ok {
		return fmt.Errorf("the lock has no entry for %s@%s", name, ref)
	}

	node, known := bb.nodes[pkg]
	if !known {
		node = bb.packageNode(pkg)
		bb.nodes[pkg] = node
		bb.nl.AddNode(node)
	}
	if err := bb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
		return err
	}
	if known {
		return nil
	}

	for _, dep := range sortedDepNames(pkg.Dependencies) {
		if err := bb.addEdge(dep, pkg.Dependencies[dep], node, sbom.Edge_dependsOn); err != nil {
			return err
		}
	}
	return nil
}

// packageNode builds the node of one fetched package. No hashes, on
// purpose: berry's checksum covers its own cache archive, which nothing
// else can reproduce.
func (bb *berryBuilder) packageNode(pkg *BerryPackage) *sbom.Node {
	return &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    pkg.Name,
		Version: pkg.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): buildPURL(pkg.Name, pkg.Version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
}

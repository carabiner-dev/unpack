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

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/license"
)

// This file turns a pnpm lock into the dependency graph. Every importer —
// the project itself and each workspace member — roots the graph with the
// identity its own package.json states, since the lock keys importers by
// directory alone. A link: reference is an edge between importers; every
// other edge resolves into the lock's package table.

type pnpmBuilder struct {
	lock    *PnpmLock
	workDir string
	opts    *api.DecomposerOptions

	nl    *sbom.NodeList
	nodes map[string]*sbom.Node // package key or importer path → node
}

func buildPnpmTree(lock *PnpmLock, workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	pb := &pnpmBuilder{
		lock:    lock,
		workDir: workDir,
		opts:    opts,
		nl:      sbom.NewNodeList(),
		nodes:   map[string]*sbom.Node{},
	}

	// The importers in stable order, every one a root. Their nodes exist
	// before any edges so link: references resolve whichever way they
	// point.
	dirs := make([]string, 0, len(lock.Importers))
	for dir := range lock.Importers {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		node, err := pb.importerNode(dir)
		if err != nil {
			return nil, err
		}
		pb.nodes["importer:"+dir] = node
		pb.nl.AddRootNode(node)
	}

	for _, dir := range dirs {
		if err := pb.importerEdges(dir); err != nil {
			return nil, err
		}
	}
	return pb.nl, nil
}

// importerNode builds the root node of one importer from the package.json
// in its directory.
func (pb *pnpmBuilder) importerNode(dir string) (*sbom.Node, error) {
	manifest, err := ParsePackageJSON(filepath.Join(pb.workDir, filepath.FromSlash(dir)))
	if err != nil {
		return nil, fmt.Errorf("importer %s: %w", dir, err)
	}

	name := manifest.Name
	if name == "" {
		name = path.Base(dir)
	}
	version := manifest.Version
	if pb.opts.Version != "" {
		version = pb.opts.Version
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
	if pb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): pb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node, nil
}

// importerEdges adds one importer's direct dependencies, each kind gated by
// its option, and walks what they pull in.
func (pb *pnpmBuilder) importerEdges(dir string) error {
	importer := pb.lock.Importers[dir]
	parent := pb.nodes["importer:"+dir]

	sections := []struct {
		deps     map[string]string
		edgeType sbom.Edge_Type
		included bool
	}{
		{importer.Dependencies, sbom.Edge_dependsOn, true},
		{importer.DevDependencies, sbom.Edge_devDependency, pb.opts.IncludeDev},
		{importer.OptionalDependencies, sbom.Edge_optionalDependency, pb.opts.IncludeOptional},
	}
	for _, section := range sections {
		if !section.included {
			continue
		}
		for _, name := range sortedDepNames(section.deps) {
			if err := pb.addEdge(dir, name, section.deps[name], parent, section.edgeType); err != nil {
				return err
			}
		}
	}
	return nil
}

// addEdge resolves one dependency reference and relates it to its parent,
// walking into it when it is new.
func (pb *pnpmBuilder) addEdge(importerDir, name, ref string, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	// A link: points at another importer, relative to this one.
	if target, isLink := strings.CutPrefix(ref, "link:"); isLink {
		linked := path.Clean(path.Join(importerDir, target))
		node, ok := pb.nodes["importer:"+linked]
		if !ok {
			return fmt.Errorf("importer %s links to %s, which the lock does not hold", importerDir, linked)
		}
		if err := pb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
			return err
		}
		// The linked importer's own edges are added on its own turn.
		return nil
	}

	key := name + "@" + ref
	pkg, ok := pb.lock.Packages[key]
	if !ok {
		return fmt.Errorf("the lock has no package for %s", key)
	}

	node, known := pb.nodes[key]
	if !known {
		node = pb.packageNode(pkg)
		pb.nodes[key] = node
		pb.nl.AddNode(node)
	}
	if err := pb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
		return err
	}
	if known {
		return nil
	}

	// The package's own edges: runtime and optional, the latter kept as
	// information — filtering transitives is the caller's business.
	for _, dep := range sortedDepNames(pkg.Dependencies) {
		if err := pb.addEdge(importerDir, dep, pkg.Dependencies[dep], node, sbom.Edge_dependsOn); err != nil {
			return err
		}
	}
	for _, dep := range sortedDepNames(pkg.OptionalDependencies) {
		if err := pb.addEdge(importerDir, dep, pkg.OptionalDependencies[dep], node, sbom.Edge_optionalDependency); err != nil {
			return err
		}
	}
	return nil
}

// packageNode builds the node of one resolved package.
func (pb *pnpmBuilder) packageNode(pkg *PnpmPackage) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    pkg.Name,
		Version: pkg.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): buildPURL(pkg.Name, pkg.Version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		UrlDownload:    pkg.Tarball,
	}
	if algorithm, hash, err := ParseIntegrity(pkg.Integrity); err == nil {
		if hashAlgo := integrityAlgorithmToSBOM(algorithm); hashAlgo != sbom.HashAlgorithm_UNKNOWN {
			node.Hashes = map[int32]string{int32(hashAlgo): fmt.Sprintf("%x", hash)}
		}
	}
	return node
}

func sortedDepNames(deps map[string]string) []string {
	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

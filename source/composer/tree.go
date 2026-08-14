// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/license"
)

// This file turns a composer.lock and its manifest into the dependency
// graph. The manifest supplies the root and says which requirements are
// direct and which of those are dev; the lock supplies everything else. A
// package appears once per lock, so resolution is by name, and platform
// requirements — php itself, extensions — are constraints on the runtime,
// not packages, and become nothing.

type composerBuilder struct {
	manifest *ComposerJSON
	opts     *api.DecomposerOptions

	nl     *sbom.NodeList
	byName map[string]*ComposerPackage
	nodes  map[string]*sbom.Node
}

func buildComposerTree(lock *ComposerLock, manifest *ComposerJSON, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	cb := &composerBuilder{
		manifest: manifest,
		opts:     opts,
		nl:       sbom.NewNodeList(),
		byName:   map[string]*ComposerPackage{},
		nodes:    map[string]*sbom.Node{},
	}

	// The whole lock resolves by name; which entries end up in the graph
	// is decided by walking from the manifest, so a dev-only package
	// appears exactly when the dev requirements were asked for.
	for _, pkg := range lock.Packages {
		cb.byName[pkg.Name] = pkg
	}
	for _, pkg := range lock.PackagesDev {
		cb.byName[pkg.Name] = pkg
	}

	root := cb.rootNode()
	cb.nl.AddRootNode(root)

	if err := cb.walkRequirements(manifest.Require, root, sbom.Edge_dependsOn); err != nil {
		return nil, err
	}
	if opts.IncludeDev {
		if err := cb.walkRequirements(manifest.RequireDev, root, sbom.Edge_devDependency); err != nil {
			return nil, err
		}
	}
	return cb.nl, nil
}

// rootNode builds the project's own node from its manifest.
func (cb *composerBuilder) rootNode() *sbom.Node {
	version := cb.manifest.Version
	if cb.opts.Version != "" {
		version = cb.opts.Version
	}

	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    cb.manifest.Name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): composerPurl(cb.manifest.Name, version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
		Description:    cb.manifest.Description,
		UrlHome:        cb.manifest.Homepage,
	}
	for _, id := range cb.manifest.Licenses() {
		node.Licenses = append(node.Licenses, license.Normalize(id, ""))
	}
	if cb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): cb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

// walkRequirements adds an edge per requirement that names a package, and
// walks into new targets.
func (cb *composerBuilder) walkRequirements(requirements map[string]string, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	names := make([]string, 0, len(requirements))
	for name := range requirements {
		if !isPlatformRequirement(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		pkg, ok := cb.byName[name]
		if !ok {
			return fmt.Errorf("the lock has no package for the requirement on %s", name)
		}

		node, known := cb.nodes[pkg.Name]
		if !known {
			node = cb.packageNode(pkg)
			cb.nodes[pkg.Name] = node
			cb.nl.AddNode(node)
		}
		if err := cb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
			return err
		}
		if known {
			continue
		}

		if err := cb.walkRequirements(pkg.Require, node, sbom.Edge_dependsOn); err != nil {
			return err
		}
	}
	return nil
}

// packageNode builds the node of one locked package. Everything on it
// comes from the lock: license, description, homepage, the archive URL and
// the source repository with its exact commit.
func (cb *composerBuilder) packageNode(pkg *ComposerPackage) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    pkg.Name,
		Version: pkg.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): composerPurl(pkg.Name, pkg.Version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		Description:    pkg.Description,
		UrlHome:        pkg.Homepage,
		UrlDownload:    pkg.Dist.URL,
	}
	for _, id := range pkg.License {
		node.Licenses = append(node.Licenses, license.Normalize(id, ""))
	}

	if pkg.Source.URL != "" {
		url := pkg.Source.URL
		if pkg.Source.Reference != "" {
			url += "#" + pkg.Source.Reference
		}
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  url,
			Type: sbom.ExternalReference_VCS,
		})
	}

	// The registry rarely states an archive hash: Packagist builds its
	// archives from the source commit, and the commit is the anchor. When
	// one is stated, it is the archive's SHA-1.
	if pkg.Dist.Shasum != "" {
		node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA1): pkg.Dist.Shasum}
	}
	return node
}

// composerPurl names a Composer package: the vendor is the purl namespace.
func composerPurl(name, version string) string {
	if version == "" {
		return "pkg:composer/" + name
	}
	return fmt.Sprintf("pkg:composer/%s@%s", name, version)
}

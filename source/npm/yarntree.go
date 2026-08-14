// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/license"
)

// This file turns a classic yarn lock into the dependency graph. The lock
// resolves ranges but classifies nothing, so the direct dependency kinds
// come from package.json, and every edge below them is a plain dependency
// unless the requiring package itself declared it optional.

type yarnBuilder struct {
	lock     *YarnLock
	manifest *PackageJSON
	opts     *api.DecomposerOptions

	nl    *sbom.NodeList
	nodes map[string]*sbom.Node // name@version → node
}

func buildYarnTree(lock *YarnLock, manifest *PackageJSON, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	yb := &yarnBuilder{
		lock:     lock,
		manifest: manifest,
		opts:     opts,
		nl:       sbom.NewNodeList(),
		nodes:    map[string]*sbom.Node{},
	}

	root := yb.rootNode()
	yb.nl.AddRootNode(root)

	sections := []struct {
		deps     map[string]string
		edgeType sbom.Edge_Type
		included bool
	}{
		{manifest.Dependencies, sbom.Edge_dependsOn, true},
		{manifest.DevDependencies, sbom.Edge_devDependency, opts.IncludeDev},
		{manifest.OptionalDependencies, sbom.Edge_optionalDependency, opts.IncludeOptional},
	}
	for _, section := range sections {
		if !section.included {
			continue
		}
		for _, name := range sortedDepNames(section.deps) {
			if err := yb.addEdge(name, section.deps[name], root, section.edgeType); err != nil {
				return nil, err
			}
		}
	}
	return yb.nl, nil
}

// rootNode builds the project's node from its manifest.
func (yb *yarnBuilder) rootNode() *sbom.Node {
	version := yb.manifest.Version
	if yb.opts.Version != "" {
		version = yb.opts.Version
	}
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    yb.manifest.Name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): buildPURL(yb.manifest.Name, version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	if yb.manifest.License != "" {
		node.Licenses = []string{license.Normalize(yb.manifest.License, "")}
	}
	if yb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): yb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

// addEdge resolves a requirement through the lock, relates it, and walks
// into it when it is new.
func (yb *yarnBuilder) addEdge(name, rang string, parent *sbom.Node, edgeType sbom.Edge_Type) error {
	pkg := yb.lock.Resolve(name, rang)
	if pkg == nil {
		return fmt.Errorf("the lock has no entry for %s@%s", name, rang)
	}

	key := pkg.Name + "@" + pkg.Version
	node, known := yb.nodes[key]
	if !known {
		node = yb.packageNode(pkg)
		yb.nodes[key] = node
		yb.nl.AddNode(node)
	}
	if err := yb.nl.RelateNodeAtID(node, parent.GetId(), edgeType); err != nil {
		return err
	}
	if known {
		return nil
	}

	for _, dep := range sortedDepNames(pkg.Dependencies) {
		if err := yb.addEdge(dep, pkg.Dependencies[dep], node, sbom.Edge_dependsOn); err != nil {
			return err
		}
	}
	for _, dep := range sortedDepNames(pkg.OptionalDependencies) {
		if err := yb.addEdge(dep, pkg.OptionalDependencies[dep], node, sbom.Edge_optionalDependency); err != nil {
			return err
		}
	}
	return nil
}

// packageNode builds the node of one resolved package.
func (yb *yarnBuilder) packageNode(pkg *YarnPackage) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    pkg.Name,
		Version: pkg.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): buildPURL(pkg.Name, pkg.Version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		UrlDownload:    pkg.Resolved,
	}

	// The integrity field may hold several hashes; the strongest one
	// becomes the node's.
	if integrity := strongestIntegrity(pkg.Integrity); integrity != "" {
		if algorithm, hash, err := ParseIntegrity(integrity); err == nil {
			if hashAlgo := integrityAlgorithmToSBOM(algorithm); hashAlgo != sbom.HashAlgorithm_UNKNOWN {
				node.Hashes = map[int32]string{int32(hashAlgo): fmt.Sprintf("%x", hash)}
			}
		}
	}
	return node
}

// strongestIntegrity picks the hash to keep from a space-separated SRI
// list, best algorithm first.
func strongestIntegrity(integrity string) string {
	fields := strings.Fields(integrity)
	for _, prefix := range []string{"sha512-", "sha384-", "sha256-", "sha1-"} {
		for _, field := range fields {
			if strings.HasPrefix(field, prefix) {
				return field
			}
		}
	}
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

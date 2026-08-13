// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
)

// This file turns a set of installed distributions into a dependency graph.
// Unlike the OS package readers, which emit a flat inventory, an installed
// Python environment carries its dependency declarations, so the graph has
// real edges: what is installed decides them. A declared dependency whose
// target is installed is an edge; one whose target is absent was for some
// other environment and is nothing. Everything is offline, licences
// included: installed metadata ships with the install.

// InstalledNodeList builds the graph an installed environment holds. When
// includeFiles is set, every file the RECORDs own becomes a node related to
// its package.
func InstalledNodeList(dists []*InstalledDistribution, includeFiles bool) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()

	// The nodes, indexed for edge resolution. The same name can appear
	// twice on a filesystem holding several environments; each occurrence
	// keeps its node, the first resolves edges.
	nodes := make([]*sbom.Node, len(dists))
	byName := map[string]*sbom.Node{}
	for i, dist := range dists {
		nodes[i] = installedNode(dist)
		if _, seen := byName[dist.Name]; !seen {
			byName[dist.Name] = nodes[i]
		}
	}

	// The edges each distribution declares, kept when the target is
	// installed. An extra-gated declaration whose target is present was
	// installed as that extra: an optional dependency in fact.
	type edge struct {
		from, to *sbom.Node
		kind     sbom.Edge_Type
	}
	edges := []edge{}
	required := map[string]bool{}
	for i, dist := range dists {
		for _, line := range dist.RequiresDist {
			req, err := parseRequirement(line)
			if err != nil {
				return nil, fmt.Errorf("%s requires %q: %w", dist.Name, line, err)
			}
			target, installed := byName[req.Name]
			if !installed || target.GetId() == nodes[i].GetId() {
				continue
			}
			kind := sbom.Edge_dependsOn
			if markerUsesExtra(req.Marker) {
				kind = sbom.Edge_optionalDependency
			}
			edges = append(edges, edge{from: nodes[i], to: target, kind: kind})
			required[req.Name] = true
		}
	}

	// The roots. The REQUESTED marker says a package was asked for rather
	// than pulled in, but only a proper subset means the installer was
	// telling packages apart: uv pip install --target stamps everything.
	// Failing that, whatever nothing here depends on is a root.
	requested := map[string]bool{}
	for _, dist := range dists {
		if dist.Requested {
			requested[dist.Name] = true
		}
	}
	useRequested := len(requested) > 0 && len(requested) < len(byName)

	for i, dist := range dists {
		isRoot := requested[dist.Name]
		if !useRequested {
			isRoot = !required[dist.Name]
		}
		if isRoot && byName[dist.Name] == nodes[i] {
			nl.AddRootNode(nodes[i])
		} else {
			nl.AddNode(nodes[i])
		}
	}

	for _, e := range edges {
		if err := nl.RelateNodeAtID(e.to, e.from.GetId(), e.kind); err != nil {
			return nil, err
		}
	}

	if includeFiles {
		for i, dist := range dists {
			if err := addInstalledFiles(nl, dist, nodes[i].GetId()); err != nil {
				return nil, err
			}
		}
	}
	return nl, nil
}

// installedNode builds the node one distribution states. Everything on it
// comes from the installed metadata: no index, no network.
func installedNode(dist *InstalledDistribution) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    dist.Name,
		Version: dist.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl(dist.Name, dist.Version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		Description:    dist.Summary,
		Licenses:       licensesFromMetadata(dist.LicenseExpression, dist.License, dist.Classifiers),
	}

	node.UrlHome = dist.HomePage
	if node.GetUrlHome() == "" {
		node.UrlHome = projectURL(dist.ProjectURLs, "homepage")
	}
	if repo := projectURL(dist.ProjectURLs, "repository", "source", "source code", "github"); repo != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  repo,
			Type: sbom.ExternalReference_VCS,
		})
	}

	// A package installed straight from a repository knows its provenance
	// down to the commit (PEP 610).
	if dist.DirectURL != nil && dist.DirectURL.URL != "" {
		url := dist.DirectURL.URL
		if commit := dist.DirectURL.VCSInfo.CommitID; commit != "" {
			url += "#" + commit
		}
		node.UrlDownload = url
		if dist.DirectURL.VCSInfo.VCS != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  url,
				Type: sbom.ExternalReference_VCS,
			})
		}
	}

	if dist.Installer != "" {
		node.Properties = append(node.Properties, &sbom.Property{
			Name: "python:installer",
			Data: dist.Installer,
		})
	}
	return node
}

// addInstalledFiles emits the files a distribution's RECORD owns, each
// related to its package. RECORD digests are urlsafe base64; the nodes
// carry them in hex, the spelling everything else uses.
func addInstalledFiles(nl *sbom.NodeList, dist *InstalledDistribution, packageID string) error {
	for _, file := range dist.Files {
		node := &sbom.Node{
			Id:       uuid.NewString(),
			Type:     sbom.Node_FILE,
			Name:     file.Path,
			FileName: file.Path,
		}
		if file.Algorithm == hashSHA256 {
			if raw, err := base64.RawURLEncoding.DecodeString(file.Digest); err == nil {
				node.Hashes = map[int32]string{
					int32(sbom.HashAlgorithm_SHA256): hex.EncodeToString(raw),
				}
			}
		}
		if err := nl.RelateNodeAtID(node, packageID, sbom.Edge_contains); err != nil {
			return err
		}
	}
	return nil
}

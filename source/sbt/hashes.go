// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbt

import (
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/unpack/source/maven"
)

// This file hashes the libraries of a snapshot. A snapshot records what
// sbt resolved and nothing about the files it fetched, so the hashes come
// from where the files are published: a Maven repository keeps, beside
// every artifact, the checksum files it was uploaded with.
//
// The snapshot does not say which repository a library came from either,
// so all of them are asked of Maven Central, as the Maven decomposer asks
// it for every POM. A library that is not there, one of an organization's
// own repository, simply gets no hash; its coordinate is still asked for.

// hashFetcher fetches the published checksums of artifacts, keyed by
// "groupId:artifactId:version" and then by algorithm name.
type hashFetcher func([]maven.Coordinate) map[string]map[string]string

// centralHashes fetches checksums from Maven Central.
func centralHashes(coords []maven.Coordinate) map[string]map[string]string {
	return maven.NewResolver(&maven.Options{}).FetchAllArtifactHashes(coords)
}

// purl qualifiers a library's coordinate is read from. sbt's dependency
// submission writes a classifier under "packaging"; the purl specification
// names it "classifier" and the file's extension "type".
const (
	qualifierPackaging  = "packaging"
	qualifierClassifier = "classifier"
	qualifierType       = "type"
)

// coordinateOf reads the Maven coordinate a library's purl states, and
// false for a node that has none to ask a repository about.
func coordinateOf(node *sbom.Node) (maven.Coordinate, bool) {
	parsed, err := purl.FromString(string(node.Purl()))
	if err != nil || parsed.Type != "maven" || parsed.Namespace == "" || parsed.Name == "" || parsed.Version == "" {
		return maven.Coordinate{}, false
	}

	coord := maven.Coordinate{
		GroupID:    parsed.Namespace,
		ArtifactID: parsed.Name,
		Version:    parsed.Version,
	}
	qualifiers := parsed.Qualifiers.Map()
	coord.Classifier = qualifiers[qualifierClassifier]
	if coord.Classifier == "" {
		coord.Classifier = qualifiers[qualifierPackaging]
	}
	coord.Type = qualifiers[qualifierType]
	return coord, true
}

// hashLibraries sets on every resolved library the checksums its
// repository publishes for it. The build's own modules are not asked
// about: they are what is being built, not something published.
func (sb *snapshotBuilder) hashLibraries(fetch hashFetcher) {
	coords := []maven.Coordinate{}
	nodes := map[string][]*sbom.Node{}
	for _, node := range sb.nodes {
		if _, isModule := sb.modules[node.GetId()]; isModule {
			continue
		}
		coord, ok := coordinateOf(node)
		if !ok {
			continue
		}
		key := coord.String()
		if _, seen := nodes[key]; !seen {
			coords = append(coords, coord)
		}
		nodes[key] = append(nodes[key], node)
	}

	for key, hashes := range fetch(coords) {
		converted := map[int32]string{}
		for algorithm, digest := range hashes {
			switch algorithm {
			case "SHA1":
				converted[int32(sbom.HashAlgorithm_SHA1)] = digest
			case "SHA256":
				converted[int32(sbom.HashAlgorithm_SHA256)] = digest
			}
		}
		if len(converted) == 0 {
			continue
		}
		for _, node := range nodes[key] {
			node.Hashes = converted
		}
	}
}

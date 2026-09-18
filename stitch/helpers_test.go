// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"github.com/protobom/protobom/pkg/sbom"
)

func pkg(id, purl string, hashes ...string) *sbom.Node {
	n := &sbom.Node{Id: id, Type: sbom.Node_PACKAGE, Name: id}
	if purl != "" {
		n.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): purl}
	}
	if len(hashes) > 0 {
		n.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): hashes[0]}
	}
	if len(hashes) > 1 {
		n.Hashes[int32(sbom.HashAlgorithm_SHA1)] = hashes[1]
	}
	return n
}

func file(id, sha256 string) *sbom.Node {
	return &sbom.Node{
		Id: id, Type: sbom.Node_FILE, Name: id,
		Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): sha256},
	}
}

// graph builds a list from "from>to" dependsOn edges over the given nodes;
// the first node is the root.
func graph(nodes []*sbom.Node, deps ...string) *sbom.NodeList {
	nl := sbom.NewNodeList()
	for i, n := range nodes {
		if i == 0 {
			nl.AddRootNode(n)
		} else {
			nl.AddNode(n)
		}
	}
	for _, d := range deps {
		var from, to string
		for i := range d {
			if d[i] == '>' {
				from, to = d[:i], d[i+1:]
			}
		}
		nl.MergeEdges([]*sbom.Edge{{From: from, Type: sbom.Edge_dependsOn, To: []string{to}}})
	}
	return nl
}

// edgeSet renders the edges as "from>to:type" by node name.
func edgeSet(nl *sbom.NodeList) []string {
	out := make([]string, 0, len(nl.GetEdges()))
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			out = append(out, nl.GetNodeByID(e.GetFrom()).GetName()+">"+nl.GetNodeByID(to).GetName()+":"+e.GetType().String())
		}
	}
	return out
}

func names(nodes []*sbom.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.GetName())
	}
	return out
}

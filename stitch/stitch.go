// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package stitch combines dependency graphs. Its primitives graft the
// subgraph of one NodeList onto a node of another, either merged into that
// node or hung below it, and collapse nodes that describe the same
// component into one. They are the building blocks for enriching an
// extraction with supplemental SBOMs, and are candidates to move into
// protobom once proven here.
package stitch

import (
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
)

// Identity reports whether two nodes describe the same component.
type Identity func(a, b *sbom.Node) bool

// SameComponent is the default Identity. Two nodes are the same component
// when they are of the same type and either share a hash under some
// algorithm with no hash disagreeing under another, or, when they share
// no hash algorithm at all, carry the same non-empty purl. A disagreeing
// hash is final: no purl overrides it.
func SameComponent(a, b *sbom.Node) bool {
	if a == nil || b == nil || a.GetType() != b.GetType() {
		return false
	}
	shared := false
	for algo, av := range a.GetHashes() {
		bv, ok := b.GetHashes()[algo]
		if !ok || av == "" || bv == "" {
			continue
		}
		if av != bv {
			return false
		}
		shared = true
	}
	if shared {
		return true
	}
	ap, bp := a.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)], b.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	return ap != "" && ap == bp
}

// Attach copies the graph reachable from rootID in src into dst, with fresh
// node ids, and relates the copy of the root to the node atID in dst with
// an edge of the given type. src is not modified.
func Attach(dst *sbom.NodeList, atID string, src *sbom.NodeList, rootID string, edgeType sbom.Edge_Type) error {
	if dst.GetNodeByID(atID) == nil {
		return fmt.Errorf("node %q not found in the destination", atID)
	}
	sub, err := copySubgraph(src, rootID)
	if err != nil {
		return err
	}
	for _, n := range sub.nodes {
		dst.AddNode(n)
	}
	dst.MergeEdges(sub.edges)
	dst.MergeEdges([]*sbom.Edge{{From: atID, Type: edgeType, To: []string{sub.rootID}}})
	return nil
}

// Merge folds the node rootID of src into the node atID of dst and copies
// the graph reachable from it below atID, with fresh node ids. The
// destination node keeps every value it has; the root fills in what it
// lacks, and its hashes, identifiers, licenses, references and properties
// are added to the destination's. Edges that left the root now leave atID.
// src is not modified.
func Merge(dst *sbom.NodeList, atID string, src *sbom.NodeList, rootID string) error {
	target := dst.GetNodeByID(atID)
	if target == nil {
		return fmt.Errorf("node %q not found in the destination", atID)
	}
	sub, err := copySubgraph(src, rootID)
	if err != nil {
		return err
	}
	for _, n := range sub.nodes {
		if n.GetId() == sub.rootID {
			absorb(target, n)
			continue
		}
		dst.AddNode(n)
	}
	for _, e := range sub.edges {
		if e.GetFrom() == sub.rootID {
			e.From = atID
		}
		for i, to := range e.GetTo() {
			if to == sub.rootID {
				e.To[i] = atID
			}
		}
	}
	dst.MergeEdges(sub.edges)
	return nil
}

// Dedupe collapses the nodes of nl that same reports as one component into
// a single node each, in place. The first of each group in list order
// survives and absorbs the others' data; every edge and root reference to
// a dropped node now names the survivor. The mapping from dropped ids to
// survivors is returned. A nil same means SameComponent.
func Dedupe(nl *sbom.NodeList, same Identity) map[string]string {
	if same == nil {
		same = SameComponent
	}
	nodes := nl.GetNodes()
	parent := make([]int, len(nodes))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	members := make(map[int][]int, len(nodes))
	for i := range nodes {
		members[i] = []int{i}
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		// The lowest index leads, so the first node in list order survives.
		if ra > rb {
			ra, rb = rb, ra
		}
		parent[rb] = ra
		members[ra] = append(members[ra], members[rb]...)
		delete(members, rb)
	}
	// A node joins a set only when it is the same component as one member
	// and its hashes disagree with none of them: identity is not
	// transitive, and a node without hashes must not bridge two nodes
	// whose hashes differ.
	compatible := func(i, set int) bool {
		for _, m := range members[set] {
			if hashesConflict(nodes[i], nodes[m]) {
				return false
			}
		}
		return true
	}

	// Candidates share a hash value or a purl; same has the last word on
	// each pair.
	groups := map[string][]int{}
	for i, n := range nodes {
		for algo, v := range n.GetHashes() {
			if v != "" {
				groups[fmt.Sprintf("h:%d:%s", algo, v)] = append(groups[fmt.Sprintf("h:%d:%s", algo, v)], i)
			}
		}
		if p := n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]; p != "" {
			groups["p:"+p] = append(groups["p:"+p], i)
		}
	}
	for _, members := range groups {
		for _, i := range members[1:] {
			for _, j := range members {
				if j == i {
					break
				}
				if find(i) == find(j) {
					break
				}
				if same(nodes[j], nodes[i]) && compatible(i, find(j)) && compatible(j, find(i)) {
					union(j, i)
					break
				}
			}
		}
	}

	dropped := map[string]string{}
	for i, n := range nodes {
		if lead := find(i); lead != i {
			absorb(nodes[lead], n)
			dropped[n.GetId()] = nodes[lead].GetId()
		}
	}
	if len(dropped) == 0 {
		return dropped
	}

	kept := make([]*sbom.Node, 0, len(nodes)-len(dropped))
	for _, n := range nodes {
		if _, gone := dropped[n.GetId()]; !gone {
			kept = append(kept, n)
		}
	}
	nl.Nodes = kept

	remap := func(id string) string {
		if to, ok := dropped[id]; ok {
			return to
		}
		return id
	}
	edges := nl.GetEdges()
	nl.Edges = nil
	for _, e := range edges {
		from := remap(e.GetFrom())
		to := make([]string, 0, len(e.GetTo()))
		for _, t := range e.GetTo() {
			if t = remap(t); t != from && !slices.Contains(to, t) {
				to = append(to, t)
			}
		}
		if len(to) > 0 {
			nl.MergeEdges([]*sbom.Edge{{From: from, Type: e.GetType(), To: to}})
		}
	}
	roots := make([]string, 0, len(nl.GetRootElements()))
	for _, r := range nl.GetRootElements() {
		if r = remap(r); !slices.Contains(roots, r) {
			roots = append(roots, r)
		}
	}
	nl.RootElements = roots
	return dropped
}

// hashesConflict reports whether a and b state different values for a hash
// algorithm they both carry.
func hashesConflict(a, b *sbom.Node) bool {
	for algo, av := range a.GetHashes() {
		if bv, ok := b.GetHashes()[algo]; ok && av != "" && bv != "" && av != bv {
			return true
		}
	}
	return false
}

// subgraph is a copy of the part of a NodeList reachable from one node.
type subgraph struct {
	rootID string
	nodes  []*sbom.Node
	edges  []*sbom.Edge
}

// copySubgraph copies the node rootID of src and everything reachable from
// it through outgoing edges, giving every node a fresh id so the copy can
// join any list without colliding with ids the source document chose.
func copySubgraph(src *sbom.NodeList, rootID string) (*subgraph, error) {
	if src == nil {
		return nil, errors.New("no source graph")
	}
	if src.GetNodeByID(rootID) == nil {
		return nil, fmt.Errorf("node %q not found in the source", rootID)
	}
	outgoing := map[string][]*sbom.Edge{}
	for _, e := range src.GetEdges() {
		outgoing[e.GetFrom()] = append(outgoing[e.GetFrom()], e)
	}

	ids := map[string]string{rootID: uuid.NewString()}
	sub := &subgraph{rootID: ids[rootID]}
	queue := []string{rootID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		n := src.GetNodeByID(id).Copy()
		n.Id = ids[id]
		sub.nodes = append(sub.nodes, n)
		for _, e := range outgoing[id] {
			copied := &sbom.Edge{From: ids[id], Type: e.GetType()}
			for _, to := range e.GetTo() {
				if src.GetNodeByID(to) == nil {
					continue // a dangling edge in the source
				}
				if _, seen := ids[to]; !seen {
					ids[to] = uuid.NewString()
					queue = append(queue, to)
				}
				copied.To = append(copied.To, ids[to])
			}
			if len(copied.GetTo()) > 0 {
				sub.edges = append(sub.edges, copied)
			}
		}
	}
	return sub, nil
}

// absorb completes dst with what src knows: scalar fields dst lacks, and
// every hash, identifier, license, reference and property src has that
// dst does not. What dst already states is kept.
func absorb(dst, src *sbom.Node) {
	dst.Augment(src)
	for algo, v := range src.GetHashes() {
		if _, ok := dst.GetHashes()[algo]; !ok && v != "" {
			if dst.Hashes == nil {
				dst.Hashes = map[int32]string{}
			}
			dst.Hashes[algo] = v
		}
	}
	for t, v := range src.GetIdentifiers() {
		if _, ok := dst.GetIdentifiers()[t]; !ok && v != "" {
			if dst.Identifiers == nil {
				dst.Identifiers = map[int32]string{}
			}
			dst.Identifiers[t] = v
		}
	}
	for _, l := range src.GetLicenses() {
		if !slices.Contains(dst.GetLicenses(), l) {
			dst.Licenses = append(dst.Licenses, l)
		}
	}
	for _, ref := range src.GetExternalReferences() {
		if !slices.ContainsFunc(dst.GetExternalReferences(), func(r *sbom.ExternalReference) bool {
			return r.GetType() == ref.GetType() && r.GetUrl() == ref.GetUrl()
		}) {
			dst.ExternalReferences = append(dst.ExternalReferences, ref)
		}
	}
	for _, p := range src.GetProperties() {
		if !slices.ContainsFunc(dst.GetProperties(), func(q *sbom.Property) bool {
			return q.GetName() == p.GetName() && q.GetData() == p.GetData()
		}) {
			dst.Properties = append(dst.Properties, p)
		}
	}
}

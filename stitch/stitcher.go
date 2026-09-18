// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"context"
	"fmt"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// PropertyStitchedFrom is set on every node a supplement was stitched
// onto, naming the source the supplement was loaded from.
const PropertyStitchedFrom = "unpack:stitched-from"

// Options configures a Stitcher.
type Options struct {
	// Identity decides which nodes the dedupe pass collapses. Nil means
	// SameComponent.
	Identity Identity

	// NoDedupe leaves duplicate nodes in place after stitching. By
	// default, nodes that two supplements, or a supplement and the
	// extraction, both describe are collapsed into one.
	NoDedupe bool
}

// Stitched records one supplement entry applied to one node.
type Stitched struct {
	// NodeID is the node in the enriched list the entry was applied to.
	NodeID string

	// Entry is the supplement entry that described it.
	Entry *Entry

	// Merged reports whether the entry was folded into the node (same
	// node type) rather than hung below it.
	Merged bool
}

// Report says what a Stitch call did.
type Report struct {
	// Stitched lists every entry applied, in the order it was applied.
	Stitched []Stitched

	// Dropped maps the ids of nodes the dedupe pass removed to the
	// nodes that survived in their place.
	Dropped map[string]string
}

// Stitcher enriches node lists with the supplements of a catalog.
type Stitcher struct {
	Catalog *Catalog
	Options Options
}

// New returns a stitcher over the catalog with the default options.
func New(catalog *Catalog) *Stitcher {
	return &Stitcher{Catalog: catalog}
}

// Stitch enriches nl in place. Every node is matched against the catalog,
// and each entry describing it is stitched onto it: an entry of the same
// node type is merged into the node, keeping what the node states and
// adding what the supplement knows, with the supplement's graph below;
// a package entry describing a file node is hung under the file with a
// generatedFrom edge, the way a decomposed binary relates to the package
// it was built from; a file entry describing a package node is hung
// under it with a contains edge. Stitched-in nodes are matched in turn,
// so supplements chain, except that a supplement never applies within
// the graph it brought in itself. Every node stitched onto gets a BOM
// reference to the supplement's document and a property naming its
// source. Unless disabled, a dedupe pass then collapses the nodes that
// now describe the same component.
func (s *Stitcher) Stitch(nl *sbom.NodeList) (*Report, error) {
	report := &Report{Dropped: map[string]string{}}
	if s.Catalog == nil || nl == nil {
		return report, nil
	}

	// origins tracks, for nodes a supplement brought in, the supplements
	// in their ancestry, so a supplement never stitches onto its own
	// graph however the chain goes.
	origins := map[string]map[*Supplement]bool{}
	queue := make([]string, 0, len(nl.GetNodes()))
	for _, n := range nl.GetNodes() {
		queue = append(queue, n.GetId())
	}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		node := nl.GetNodeByID(id)
		if node == nil {
			continue
		}
		for _, entry := range s.Catalog.Match(node) {
			if origins[id][entry.Supplement] {
				continue
			}
			before := len(nl.GetNodes())
			merged, err := apply(nl, node, entry)
			if err != nil {
				return report, fmt.Errorf("stitching %s onto %s: %w", entry.Supplement.Source, node.GetName(), err)
			}
			entry.Used = true
			report.Stitched = append(report.Stitched, Stitched{NodeID: id, Entry: entry, Merged: merged})

			// Whatever came in is matched next, remembering where it
			// came from.
			ancestry := map[*Supplement]bool{entry.Supplement: true}
			for sup := range origins[id] {
				ancestry[sup] = true
			}
			for _, added := range nl.GetNodes()[before:] {
				origins[added.GetId()] = ancestry
				queue = append(queue, added.GetId())
			}
			if merged {
				// The node itself now carries the supplement's data;
				// its own ancestry grows so the supplement does not
				// reapply to it or below it.
				if origins[id] == nil {
					origins[id] = map[*Supplement]bool{}
				}
				origins[id][entry.Supplement] = true
			}
		}
	}

	if !s.Options.NoDedupe {
		report.Dropped = Dedupe(nl, s.Options.Identity)
	}
	return report, nil
}

// apply stitches one entry onto one node and records the provenance on
// the node. It reports whether the entry was merged rather than attached.
func apply(nl *sbom.NodeList, node *sbom.Node, entry *Entry) (bool, error) {
	src := entry.Supplement.Document.GetNodeList()
	merged := false
	switch {
	case node.GetType() == entry.Node.GetType():
		if err := Merge(nl, node.GetId(), src, entry.ID()); err != nil {
			return false, err
		}
		merged = true
	case node.GetType() == sbom.Node_FILE:
		if err := Attach(nl, node.GetId(), src, entry.ID(), sbom.Edge_generatedFrom); err != nil {
			return false, err
		}
	default:
		if err := Attach(nl, node.GetId(), src, entry.ID(), sbom.Edge_contains); err != nil {
			return false, err
		}
	}

	ref := &sbom.ExternalReference{
		Type:    sbom.ExternalReference_BOM,
		Url:     entry.Supplement.Document.GetMetadata().GetId(),
		Comment: "stitched from " + entry.Supplement.Source,
	}
	if ref.GetUrl() == "" {
		ref.Url = entry.Supplement.Source
	}
	node.ExternalReferences = append(node.ExternalReferences, ref)
	node.Properties = append(node.Properties, &sbom.Property{Name: PropertyStitchedFrom, Data: entry.Supplement.Source})
	return merged, nil
}

// Unpacker wraps another unpacker and stitches the catalog's supplements
// into everything it extracts. It satisfies api.Unpacker, so it stands in
// for the inner unpacker wherever one is used.
type Unpacker struct {
	Inner    api.Unpacker
	Stitcher *Stitcher

	// Reports collects the report of every list stitched, in order.
	Reports []*Report
}

var _ api.Unpacker = (*Unpacker)(nil)

// Wrap returns an unpacker that runs inner and stitches its results with
// the catalog's supplements.
func Wrap(inner api.Unpacker, catalog *Catalog) *Unpacker {
	return &Unpacker{Inner: inner, Stitcher: New(catalog)}
}

// Extract runs the inner unpacker and stitches every list it returns.
// Lists returned alongside an error are stitched too, since the inner
// unpacker chose to return them.
func (u *Unpacker) Extract(ctx context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
	lists, err := u.Inner.Extract(ctx, subject)
	for _, nl := range lists {
		report, serr := u.Stitcher.Stitch(nl)
		u.Reports = append(u.Reports, report)
		if serr != nil {
			return lists, serr
		}
	}
	return lists, err
}

// RegisterDecomposer registers with the inner unpacker.
func (u *Unpacker) RegisterDecomposer(d api.Decomposer) { u.Inner.RegisterDecomposer(d) }

// UnregisterDecomposer unregisters from the inner unpacker.
func (u *Unpacker) UnregisterDecomposer(d api.Decomposer) { u.Inner.UnregisterDecomposer(d) }

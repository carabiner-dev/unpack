// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	protosbom "github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/unpack/sbom"
)

// Supplement is a bill of materials loaded to enrich an extraction: the
// document and where it came from.
type Supplement struct {
	// Source is the path the document was read from.
	Source string

	// Document is the parsed bill of materials. Its node list is what gets
	// stitched; its metadata identifies it for provenance.
	Document *protosbom.Document

	// Entries are the components the document describes, one per root
	// element, in document order.
	Entries []*Entry
}

// Entry is one component a supplement describes: a root element of its
// document, which the catalog matches against nodes found in an
// extraction. The graph below it is what gets stitched under the match.
type Entry struct {
	Supplement *Supplement

	// Node is the described component as the supplement states it.
	Node *protosbom.Node

	// Used records that the entry matched something during stitching, so
	// supplements nobody asked for can be reported.
	Used bool
}

// ID returns the id of the described component in the supplement's list.
func (e *Entry) ID() string { return e.Node.GetId() }

// Catalog holds supplements and finds the entries describing a node by its
// hashes or purl.
type Catalog struct {
	supplements []*Supplement
	byHash      map[string][]*Entry
	byPurl      map[string][]*Entry

	// unparsed lists the files a directory walk skipped because they did
	// not parse as a bill of materials.
	unparsed []string
}

// NewCatalog returns an empty catalog.
func NewCatalog() *Catalog {
	return &Catalog{byHash: map[string][]*Entry{}, byPurl: map[string][]*Entry{}}
}

// Load reads supplements from the given paths. A path naming a file must
// parse as a bill of materials, bare or enveloped. A path naming a
// directory is walked, and every regular file in it that parses is added;
// the rest are skipped and listed by Unparsed, since a directory of
// documents may hold a README next to them.
func (c *Catalog) Load(paths ...string) error {
	var errs []error
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("reading supplement path: %w", err))
			continue
		}
		if !info.IsDir() {
			if err := c.LoadFile(path); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if err := c.LoadFile(p); err != nil {
				logrus.Debugf("skipping %s: %v", p, err)
				c.unparsed = append(c.unparsed, p)
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("walking supplement directory %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

// LoadFile reads one supplement from a file.
func (c *Catalog) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening supplement: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	doc, err := sbom.ParseDocument(f)
	if err != nil {
		return fmt.Errorf("reading supplement %s: %w", path, err)
	}
	c.Add(path, doc)
	return nil
}

// Add registers a parsed document as a supplement, indexing the
// components it describes. A document that describes nothing is kept but
// can never match.
func (c *Catalog) Add(source string, doc *protosbom.Document) *Supplement {
	sup := &Supplement{Source: source, Document: doc}
	nl := doc.GetNodeList()
	for _, id := range nl.GetRootElements() {
		n := nl.GetNodeByID(id)
		if n == nil {
			continue
		}
		e := &Entry{Supplement: sup, Node: n}
		sup.Entries = append(sup.Entries, e)
		for algo, v := range n.GetHashes() {
			if v != "" {
				c.byHash[hashKey(algo, v)] = append(c.byHash[hashKey(algo, v)], e)
			}
		}
		if p := purlOf(n); p != "" {
			c.byPurl[p] = append(c.byPurl[p], e)
		}
	}
	c.supplements = append(c.supplements, sup)
	return sup
}

// Match returns the entries describing the node, in catalog order. An
// entry describes a node under sbom.SameComponent's rule, minus the node
// type: they share a hash under some algorithm and disagree under none,
// or, when they share no hash algorithm, they carry the same purl. A
// package in a document may well describe a file found on disk, and the
// stitcher decides what that means.
func (c *Catalog) Match(n *protosbom.Node) []*Entry {
	seen := map[*Entry]bool{}
	var found []*Entry
	for algo, v := range n.GetHashes() {
		if v == "" {
			continue
		}
		for _, e := range c.byHash[hashKey(algo, v)] {
			if !seen[e] && !n.HashesConflict(e.Node) {
				seen[e] = true
				found = append(found, e)
			}
		}
	}
	if p := purlOf(n); p != "" {
		for _, e := range c.byPurl[p] {
			if !seen[e] && !sharesHashAlgorithm(n, e.Node) {
				seen[e] = true
				found = append(found, e)
			}
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return c.order(found[i]) < c.order(found[j]) })
	return found
}

// order ranks an entry by its position in the catalog: supplement first,
// entry within it second.
func (c *Catalog) order(e *Entry) int {
	for i, s := range c.supplements {
		if s != e.Supplement {
			continue
		}
		for j, x := range s.Entries {
			if x == e {
				return i*1000 + j
			}
		}
	}
	return -1
}

// Supplements returns the loaded supplements in load order.
func (c *Catalog) Supplements() []*Supplement { return c.supplements }

// Entries returns every entry of every supplement in catalog order.
func (c *Catalog) Entries() []*Entry {
	var out []*Entry
	for _, s := range c.supplements {
		out = append(out, s.Entries...)
	}
	return out
}

// Unused returns the entries that matched nothing, so the caller can tell
// the user which supplements went unused.
func (c *Catalog) Unused() []*Entry {
	var out []*Entry
	for _, e := range c.Entries() {
		if !e.Used {
			out = append(out, e)
		}
	}
	return out
}

// Unparsed returns the files a directory walk skipped because they did
// not parse as a bill of materials.
func (c *Catalog) Unparsed() []string { return c.unparsed }

func hashKey(algo int32, v string) string { return fmt.Sprintf("%d:%s", algo, v) }

// purlOf returns the node's purl identifier whatever its type. protobom's
// Node.Purl hides purls on file nodes; the catalog wants them.
func purlOf(n *protosbom.Node) string {
	return n.GetIdentifiers()[int32(protosbom.SoftwareIdentifierType_PURL)]
}

// sharesHashAlgorithm reports whether both nodes state a hash under one
// same algorithm.
func sharesHashAlgorithm(a, b *protosbom.Node) bool {
	for algo, av := range a.GetHashes() {
		if bv, ok := b.GetHashes()[algo]; ok && av != "" && bv != "" {
			return true
		}
	}
	return false
}

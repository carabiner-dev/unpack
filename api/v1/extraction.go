// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"slices"

	"github.com/protobom/protobom/pkg/sbom"
)

// Extraction is one graph read from a subject, with what is known of how
// it was read. A node list holds components and how they relate; what an
// unpacker learns beyond that, which is a document's to state and not a
// component's, travels beside it here.
type Extraction struct {
	// NodeList is the graph.
	NodeList *sbom.NodeList

	// Contexts are the contexts the graph's data was read in: those of
	// the decomposers that contributed to it, each once, in a fixed
	// order. A graph put together from several decomposers can hold
	// more than one, as an image does that carries both its system's
	// packages and an application's own record of what it was built
	// from. Empty when no decomposer behind the graph says.
	Contexts []GenerationContext
}

// NewExtraction returns the extraction of a graph read in the given
// contexts.
func NewExtraction(nl *sbom.NodeList, contexts ...GenerationContext) *Extraction {
	e := &Extraction{NodeList: nl}
	e.AddContexts(contexts...)
	return e
}

// AddContexts records contexts the graph's data was read in. One already
// recorded is not recorded again, and they are kept sorted, so that the
// order decomposers happened to run in does not show.
func (e *Extraction) AddContexts(contexts ...GenerationContext) {
	for _, generation := range contexts {
		if !slices.Contains(e.Contexts, generation) {
			e.Contexts = append(e.Contexts, generation)
		}
	}
	slices.Sort(e.Contexts)
}

// AddContextOf records the context a decomposer reads in, when it says.
func (e *Extraction) AddContextOf(d Decomposer) {
	if generation, ok := GenerationContextOf(d); ok {
		e.AddContexts(generation)
	}
}

// ExtractionUnpacker is implemented by unpackers that can say, with each
// graph they return, in what context it was read. It is Unpacker.Extract
// with more to tell: the node lists are the same ones.
type ExtractionUnpacker interface {
	// Extractions reads dependency data from the given subject and
	// returns the resulting graphs, each with its contexts.
	Extractions(context.Context, DecomposableSubject) ([]*Extraction, error)
}

// Extractions reads a subject with an unpacker and returns its graphs with
// what the unpacker can say of them. One that does not implement
// ExtractionUnpacker has its node lists returned with nothing said.
//
// Like Unpacker.Extract, it may return graphs together with an error, when
// part of a subject could be read and part could not.
func Extractions(ctx context.Context, u Unpacker, subject DecomposableSubject) ([]*Extraction, error) {
	if eu, ok := u.(ExtractionUnpacker); ok {
		return eu.Extractions(ctx, subject)
	}
	lists, err := u.Extract(ctx, subject)
	extractions := make([]*Extraction, 0, len(lists))
	for _, nl := range lists {
		extractions = append(extractions, NewExtraction(nl))
	}
	return extractions, err
}

// NodeLists returns the graphs of a list of extractions, which is what
// Unpacker.Extract returns.
func NodeLists(extractions []*Extraction) []*sbom.NodeList {
	if extractions == nil {
		return nil
	}
	lists := make([]*sbom.NodeList, 0, len(extractions))
	for _, e := range extractions {
		lists = append(lists, e.NodeList)
	}
	return lists
}

// MergedContexts returns every context of a list of extractions, each
// once, sorted: what a graph assembled from all of them was read in.
func MergedContexts(extractions []*Extraction) []GenerationContext {
	merged := &Extraction{}
	for _, e := range extractions {
		merged.AddContexts(e.Contexts...)
	}
	return merged.Contexts
}

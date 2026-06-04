// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package sbom implements the unpacker that reads dependency data from a
// software bill of materials.
package sbom

import (
	"context"
	"fmt"

	"github.com/protobom/protobom/pkg/reader"
	protosbom "github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// Ensure the SBOM unpacker satisfies the unified Unpacker interface.
var _ api.Unpacker = (*Unpacker)(nil)

// Register the SBOM unpacker so that subjects of type "sbom" are routed here by
// the registry.
func init() {
	api.RegisterUnpacker("sbom", func() api.Unpacker { return NewUnpacker() })
}

// NewUnpacker returns a ready-to-use SBOM unpacker.
func NewUnpacker() *Unpacker {
	return &Unpacker{}
}

// Unpacker reads dependency data out of an existing SBOM document. It has no
// decomposers: the SBOM format itself is the subject matter, parsed directly.
type Unpacker struct{}

// Extract parses the SBOM in the subject and returns its node list.
func (u *Unpacker) Extract(_ context.Context, subject api.DecomposableSubject) ([]*protosbom.NodeList, error) {
	if subject == nil {
		return nil, fmt.Errorf("sbom unpacker received a nil subject")
	}
	s, ok := subject.(*Subject)
	if !ok {
		return nil, fmt.Errorf(
			"sbom unpacker cannot process subject of type %q", subject.DecomposableType(),
		)
	}

	r, closeFn, err := s.open()
	if err != nil {
		return nil, err
	}
	defer closeFn() //nolint:errcheck // best-effort close of read-only source

	doc, err := reader.New().ParseStream(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM data: %w", err)
	}

	return []*protosbom.NodeList{doc.GetNodeList()}, nil
}

// RegisterDecomposer is a no-op: the SBOM unpacker has no decomposers.
func (u *Unpacker) RegisterDecomposer(api.Decomposer) {}

// UnregisterDecomposer is a no-op: the SBOM unpacker has no decomposers.
func (u *Unpacker) UnregisterDecomposer(api.Decomposer) {}

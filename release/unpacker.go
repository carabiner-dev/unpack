// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"fmt"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// Ensure the release unpacker satisfies the unified Unpacker interface.
var _ api.Unpacker = (*Unpacker)(nil)

// Register the release unpacker so that subjects of type "release" are routed
// here by the registry.
func init() {
	api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}

// NewUnpacker returns a release unpacker pre-loaded with the default release
// decomposer.
func NewUnpacker() *Unpacker {
	u := &Unpacker{
		decomposers: map[string]api.Decomposer{},
	}
	u.RegisterDecomposer(NewDecomposer())
	return u
}

// Unpacker is the release unpacker. It runs each registered decomposer
// against the release the subject points to and aggregates the resulting
// NodeLists.
type Unpacker struct {
	decomposers map[string]api.Decomposer
}

// Extract reads the release the given subject points to and returns the
// NodeLists produced by the registered decomposers.
func (u *Unpacker) Extract(ctx context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
	if subject == nil {
		return nil, fmt.Errorf("release unpacker received a nil subject")
	}
	ref, ok := subject.(*Reference)
	if !ok {
		return nil, fmt.Errorf(
			"release unpacker cannot process subject of type %q", subject.DecomposableType(),
		)
	}

	var nodelists []*sbom.NodeList
	var errs []error
	for name, d := range u.decomposers {
		opts := &api.DecomposerOptions{}
		opts.SetDriverOptions(d, &Options{Reference: ref})

		var nl *sbom.NodeList
		var err error
		if rd, isRelease := d.(*Decomposer); isRelease {
			nl, err = rd.ExtractRelease(ctx, ref, opts)
		} else {
			nl, err = d.Extract(opts)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("decomposer %q: %w", name, err))
			continue
		}
		if nl == nil {
			continue
		}
		nodelists = append(nodelists, nl)
	}
	if len(errs) > 0 {
		return nodelists, errors.Join(errs...)
	}
	return nodelists, nil
}

// RegisterDecomposer adds a decomposer to the unpacker.
func (u *Unpacker) RegisterDecomposer(d api.Decomposer) {
	u.decomposers[fmt.Sprintf("%T", d)] = d
}

// UnregisterDecomposer removes a decomposer from the unpacker.
func (u *Unpacker) UnregisterDecomposer(d api.Decomposer) {
	delete(u.decomposers, fmt.Sprintf("%T", d))
}

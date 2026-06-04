// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system/rpm"
)

// Ensure the system unpacker satisfies the unified Unpacker interface.
var _ api.Unpacker = (*Unpacker)(nil)

// Register the SystemPackages unpacker so that subjects of type "system" are
// routed here by the registry.
func init() {
	api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}

// NewUnpacker returns a SystemPackages unpacker pre-loaded with the default
// system decomposers.
func NewUnpacker() *Unpacker {
	return &Unpacker{
		decomposers: map[string]SystemDecomposer{
			"rpm": rpm.New(),
		},
	}
}

// Unpacker is the SystemPackages unpacker. It runs each configured
// SystemDecomposer against the subject's filesystem and aggregates the
// resulting NodeLists.
type Unpacker struct {
	decomposers map[string]SystemDecomposer
}

// Extract reads installed-package data from the given system subject. Each
// decomposer that produces a NodeList contributes one entry to the result; a
// decomposer that doesn't find its database returns (nil, nil) and is
// skipped.
func (u *Unpacker) Extract(_ context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
	if subject == nil {
		return nil, fmt.Errorf("system unpacker received a nil subject")
	}
	s, ok := subject.(System)
	if !ok {
		return nil, fmt.Errorf(
			"system unpacker cannot process subject of type %q", subject.DecomposableType(),
		)
	}

	src, err := s.FileSystem()
	if err != nil {
		return nil, fmt.Errorf("opening system filesystem: %w", err)
	}

	opts := &api.DecomposerOptions{}
	var nodelists []*sbom.NodeList
	var errs []error
	for name, d := range u.decomposers {
		nl, err := d.ExtractFromFS(src, opts)
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

// RegisterDecomposer adds a decomposer to the unpacker. The decomposer must
// implement SystemDecomposer; other decomposers are rejected silently to
// match the existing Unpacker interface (which can't return an error here).
func (u *Unpacker) RegisterDecomposer(d api.Decomposer) {
	sd, ok := d.(SystemDecomposer)
	if !ok {
		return
	}
	u.decomposers[fmt.Sprintf("%T", d)] = sd
}

// UnregisterDecomposer removes a decomposer from the unpacker.
func (u *Unpacker) UnregisterDecomposer(d api.Decomposer) {
	delete(u.decomposers, fmt.Sprintf("%T", d))
}

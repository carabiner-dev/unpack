// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system/apk"
	"github.com/carabiner-dev/unpack/system/composer"
	"github.com/carabiner-dev/unpack/system/deb"
	"github.com/carabiner-dev/unpack/system/python"
	"github.com/carabiner-dev/unpack/system/rpm"
)

// Ensure the system unpacker satisfies the unified Unpacker interface.
var _ api.Unpacker = (*Unpacker)(nil)

// Register the SystemPackages unpacker so that subjects of type "system" are
// routed here by the registry.
func init() {
	api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}

// Options configures the SystemPackages unpacker.
type Options struct {
	// IncludeFiles instructs system decomposers to emit a Node for every file
	// installed by each package, related to the package via a "contains"
	// edge. Off by default because it can multiply node count by a large
	// factor (a typical RHEL system has ~10⁵ files).
	IncludeFiles bool
}

// DefaultOptions is the zero-value configuration used by NewUnpacker.
var DefaultOptions = Options{}

// NewUnpacker returns a SystemPackages unpacker pre-loaded with the default
// system decomposers.
func NewUnpacker() *Unpacker {
	return &Unpacker{
		Options: DefaultOptions,
		decomposers: map[string]SystemDecomposer{
			"rpm":      rpm.New(),
			"deb":      deb.New(),
			"apk":      apk.New(),
			"python":   python.New(),
			"composer": composer.New(),
		},
	}
}

// Unpacker is the SystemPackages unpacker. It runs each configured
// SystemDecomposer against the subject's filesystem and aggregates the
// resulting NodeLists.
type Unpacker struct {
	Options     Options
	decomposers map[string]SystemDecomposer
}

// Extract reads installed-package data from the given system subject. Each
// decomposer that produces a NodeList contributes one entry to the result; a
// decomposer that doesn't find its database returns (nil, nil) and is
// skipped.
func (u *Unpacker) Extract(ctx context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
	extractions, err := u.Extractions(ctx, subject)
	return api.NodeLists(extractions), err
}

var _ api.ExtractionUnpacker = (*Unpacker)(nil)

// Extractions is Extract, returning with each NodeList the context its
// decomposer reads in.
func (u *Unpacker) Extractions(_ context.Context, subject api.DecomposableSubject) ([]*api.Extraction, error) {
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

	opts := &api.DecomposerOptions{
		IncludeFiles: u.Options.IncludeFiles,
	}
	var extractions []*api.Extraction
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
		extraction := api.NewExtraction(nl)
		extraction.AddContextOf(d)
		extractions = append(extractions, extraction)
	}
	if len(errs) > 0 {
		return extractions, errors.Join(errs...)
	}
	return extractions, nil
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

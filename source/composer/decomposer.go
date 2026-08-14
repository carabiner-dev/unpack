// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var (
	_ api.Decomposer       = (*Decomposer)(nil)
	_ api.SourceDecomposer = (*Decomposer)(nil)
)

// New returns a ready-to-use Composer decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from PHP codebases managed by Composer.
type Decomposer struct{}

// Options configures the Composer decomposer. There are none yet: the lock
// carries everything, licenses included.
type Options struct{}

// DefaultOptions returns the driver-level options used when none are set.
func (d *Decomposer) DefaultOptions() any { return Options{} }

// Requirements returns nothing: extraction is pure Go, offline.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// FindCodeBases locates PHP codebases by their composer.lock files.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("composer.lock")
}

// Extract reads composer.lock and composer.json and builds the graph.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	lock, err := ReadComposerLock(workDir)
	if err != nil {
		return nil, err
	}
	manifest, err := ReadComposerJSON(workDir)
	if err != nil {
		return nil, err
	}
	return buildComposerTree(lock, manifest, opts)
}

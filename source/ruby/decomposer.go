// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var (
	_ api.Decomposer       = (*Decomposer)(nil)
	_ api.SourceDecomposer = (*Decomposer)(nil)
)

// New returns a ready-to-use Ruby decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from Ruby codebases managed by Bundler.
type Decomposer struct{}

// Options configures the Ruby dependency extraction.
type Options struct {
	// Platform targets an operating system and architecture, as os[/arch]
	// in Go's vocabulary; it selects among a gem's platform variants and
	// outranks the generic --platform. Empty means the platform unpack
	// runs on.
	Platform string
}

// DefaultOptions returns the default options for the Ruby decomposer.
func (d *Decomposer) DefaultOptions() any { return Options{} }

// Requirements returns nothing: extraction is pure Go, offline.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// FindCodeBases locates Ruby codebases by their Gemfile.lock files.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("Gemfile.lock")
}

// Extract reads Gemfile.lock and builds the graph the target platform
// sees.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	lock, err := ReadGemLockfile(workDir)
	if err != nil {
		return nil, err
	}

	platform := ""
	if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok && dOpts.Platform != "" {
		platform = dOpts.Platform
	} else if opts.Platform != "" {
		platform = opts.Platform
	}

	return buildRubyTree(lock, workDir, opts, platform)
}

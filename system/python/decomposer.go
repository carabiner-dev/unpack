// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package python implements a SystemDecomposer that reads the Python
// distributions installed on a filesystem: the *.dist-info directories in
// its site-packages, wherever they live — system interpreters, virtualenvs,
// pip --target trees. This is how a container image says what Python
// software it holds, and it works with no lockfile, no network and no
// Python interpreter.
//
// Unlike the OS package decomposers, which emit a flat inventory, the
// result is a graph: installed metadata declares dependencies, and a
// declaration whose target is installed is an edge.
package python

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	python "github.com/carabiner-dev/unpack/source/python"
)

var _ api.Decomposer = (*Decomposer)(nil)

// New returns a ready-to-use Python system decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads installed Python distributions from a system filesystem.
type Decomposer struct{}

// Options configures the decomposer. There are none yet: discovery walks
// the filesystem, so there are no database locations to override.
type Options struct{}

// DefaultOptions returns the driver-level options used when none are set.
func (d *Decomposer) DefaultOptions() any { return Options{} }

// Requirements returns nothing: reading dist-info is pure Go.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// Extract opens opts.WorkDir as the system root and runs the FS-aware
// extractor against it, mirroring the other system decomposers.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("python system decomposer needs a WorkDir to use as the system root")
	}
	return d.ExtractFromFS(os.DirFS(opts.WorkDir), opts)
}

// ExtractFromFS reads every installed distribution on the filesystem and
// returns their graph. Returns (nil, nil) when the filesystem holds no
// Python at all, which is not an error.
func (d *Decomposer) ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	dists, err := python.FindDistributions(source)
	if err != nil {
		return nil, fmt.Errorf("scanning for installed distributions: %w", err)
	}
	if len(dists) == 0 {
		return nil, nil
	}
	return python.InstalledNodeList(dists, opts != nil && opts.IncludeFiles)
}

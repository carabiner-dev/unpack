// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package composer implements a SystemDecomposer that reads the Composer
// packages installed on a filesystem: the installed.json each vendor
// directory carries, wherever it lives. This is how a container image says
// what PHP software it holds, with the dependency graph and every license
// read offline from the installed metadata.
package composer

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	phpcomposer "github.com/carabiner-dev/unpack/source/composer"
)

var _ api.Decomposer = (*Decomposer)(nil)

// New returns a ready-to-use Composer system decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads installed Composer packages from a system filesystem.
type Decomposer struct{}

// Options configures the decomposer. There are none yet: discovery walks
// the filesystem.
type Options struct{}

// DefaultOptions returns the driver-level options used when none are set.
func (d *Decomposer) DefaultOptions() any { return Options{} }

// Requirements returns nothing: reading installed.json is pure Go.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// Extract opens opts.WorkDir as the system root and runs the FS-aware
// extractor against it, mirroring the other system decomposers.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("composer system decomposer needs a WorkDir to use as the system root")
	}
	return d.ExtractFromFS(os.DirFS(opts.WorkDir), opts)
}

// ExtractFromFS reads every installed Composer environment on the
// filesystem and returns their graph. Returns (nil, nil) when the
// filesystem holds no Composer at all, which is not an error.
func (d *Decomposer) ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	nl, err := phpcomposer.ExtractInstalled(source, opts)
	if err != nil {
		return nil, fmt.Errorf("scanning for installed composer packages: %w", err)
	}
	return nl, nil
}

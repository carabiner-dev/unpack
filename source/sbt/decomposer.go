// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package sbt reads the dependency data of sbt builds.
//
// An sbt build is Scala code: what it depends on is only known once sbt has
// loaded the build and resolved it. The decomposer does not do that. It
// reads the dependency snapshot sbt-dependency-submission writes for GitHub
// (githubGenerateSnapshot), which sbt produced from its own resolution,
// and so it only runs when pointed at one.
package sbt

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var (
	_ api.Decomposer       = (*Decomposer)(nil)
	_ api.SourceDecomposer = (*Decomposer)(nil)
)

// buildFile marks the root of an sbt build.
const buildFile = "build.sbt"

// New returns an sbt decomposer reading the dependency snapshot at
// snapshotPath.
func New(snapshotPath string) *Decomposer {
	return &Decomposer{SnapshotPath: snapshotPath}
}

// Decomposer reads the dependency data of sbt builds from a GitHub
// dependency snapshot.
type Decomposer struct {
	// SnapshotPath is the dependency snapshot of the build.
	SnapshotPath string

	once     sync.Once
	snapshot *Snapshot
	err      error
}

// DefaultOptions returns nothing: the decomposer takes no driver options,
// the snapshot is what configures it.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: sbt already ran, reading its output is
// pure Go and offline.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// load reads the snapshot once.
func (d *Decomposer) load() (*Snapshot, error) {
	d.once.Do(func() {
		if d.SnapshotPath == "" {
			d.err = errors.New("the sbt decomposer needs a dependency snapshot to read")
			return
		}
		d.snapshot, d.err = ReadSnapshot(d.SnapshotPath)
	})
	return d.snapshot, d.err
}

// FindCodeBases locates the build the snapshot describes.
//
// A tree can hold many sbt builds (scripted test fixtures carry their own
// build.sbt) but a snapshot describes one. Its manifests name the build
// file relative to the workspace, so the candidates are the directories
// holding a build.sbt at that path, and of those the shallowest: the
// workspace itself when the build is at its root.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	snapshot, err := d.load()
	if err != nil {
		return nil, err
	}

	locations, err := index.FindFileLocations(buildFile)
	if err != nil {
		return nil, err
	}

	buildDir := snapshot.buildDir()
	var candidates []string
	for _, loc := range locations {
		clean := filepath.Clean(loc)
		if buildDir != "" && clean != buildDir &&
			!strings.HasSuffix(clean, string(filepath.Separator)+buildDir) {
			continue
		}
		candidates = append(candidates, loc)
	}

	return shallowest(candidates), nil
}

// buildDir returns the directory of the build relative to the workspace,
// as the manifests record it. It returns nothing when the build is at the
// root of the workspace or its location is unknown: sbt records an
// absolute path when the build is outside the workspace, which says
// nothing about where it is here.
func (s *Snapshot) buildDir() string {
	for _, m := range s.Manifests {
		if m.File == nil || m.File.SourceLocation == "" {
			continue
		}
		dir := filepath.Dir(filepath.Clean(filepath.FromSlash(m.File.SourceLocation)))
		if dir == "." || filepath.IsAbs(dir) {
			return ""
		}
		return dir
	}
	return ""
}

// shallowest returns the paths with the fewest elements.
func shallowest(paths []string) []string {
	depth := func(p string) int {
		return strings.Count(filepath.Clean(p), string(filepath.Separator))
	}
	minDepth := -1
	for _, p := range paths {
		if d := depth(p); minDepth == -1 || d < minDepth {
			minDepth = d
		}
	}
	ret := make([]string, 0, len(paths))
	for _, p := range paths {
		if depth(p) == minDepth {
			ret = append(ret, p)
		}
	}
	return ret
}

// Extract builds the dependency graph of the build from the snapshot.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	snapshot, err := d.load()
	if err != nil {
		return nil, err
	}

	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	nl, err := newSnapshotBuilder(snapshot, workDir, opts).build()
	if err != nil {
		return nil, fmt.Errorf("building graph from dependency snapshot: %w", err)
	}
	return nl, nil
}

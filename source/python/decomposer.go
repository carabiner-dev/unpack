// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var (
	_ api.Decomposer       = (*Decomposer)(nil)
	_ api.SourceDecomposer = (*Decomposer)(nil)
)

func New() *Decomposer {
	return &Decomposer{}
}

// Decomposer reads dependency data from Python codebases managed by uv. The
// whole graph comes from uv.lock: versions, edges, markers and artifact
// hashes are all resolved in the lock, so extraction needs no network and no
// Python interpreter.
type Decomposer struct{}

// Options configures the Python dependency extraction.
type Options struct {
	// Platform targets an operating system and architecture, in GOOS/GOARCH
	// vocabulary ("linux/arm64"), an os alone ("windows"), or empty for the
	// platform unpack runs on. A lockfile resolves for every platform at
	// once; the extraction reads it for this one.
	Platform string

	// PythonVersion targets an interpreter version, "3.12" or fuller.
	// Empty picks the newest version the lockfile's own resolution forks
	// mention, so the default describes a current install with no Python
	// on the machine unpack runs on.
	PythonVersion string

	// Concurrency controls the parallel requests to PyPI when enriching
	// (default: 10).
	Concurrency int
}

// DefaultOptions returns the default options for the Python decomposer.
func (d *Decomposer) DefaultOptions() any {
	return Options{}
}

// Requirements returns nothing: extraction is pure Go, offline.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement {
	return nil
}

// FindCodeBases locates Python codebases by their uv.lock files.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("uv.lock")
}

// Extract reads uv.lock and builds the dependency graph the target
// environment sees.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	lock, err := ReadLockfile(filepath.Join(workDir, "uv.lock"))
	if err != nil {
		return nil, err
	}

	dOpts := d.getOptions(opts)
	env, err := d.environment(dOpts, opts, lock)
	if err != nil {
		return nil, err
	}

	tb := newTreeBuilder(lock, env, opts)
	nl, err := tb.build()
	if err != nil {
		return nil, err
	}

	// Locks carry no licence data at all, so without the index every
	// Python SBOM is licence-empty. Enrichment fills what PyPI knows.
	if opts.Networking >= api.NetworkEssential {
		tb.enrich(NewPyPIClient(dOpts.Concurrency))
	}

	return nl, nil
}

// getOptions extracts Python-specific options from DecomposerOptions.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	return &Options{}
}

// environment builds the target environment the extraction resolves for.
// The driver's own platform outranks the generic one, so a programmatic
// caller can pin Python somewhere else than the rest of an extraction.
func (d *Decomposer) environment(dOpts *Options, opts *api.DecomposerOptions, lock *Lockfile) (*Environment, error) {
	platform := dOpts.Platform
	if platform == "" && opts != nil {
		platform = opts.Platform
	}
	goos, goarch, _ := strings.Cut(platform, "/")

	pythonVersion := dOpts.PythonVersion
	if pythonVersion == "" {
		pythonVersion = defaultPythonVersion(lock)
	}

	env, err := NewEnvironment(goos, goarch, pythonVersion)
	if err != nil {
		return nil, fmt.Errorf("building the target environment: %w", err)
	}
	return env, nil
}

// pythonVersionLiterals finds the version literals a marker or specifier
// compares Python versions against.
var pythonVersionLiterals = regexp.MustCompile(
	`python(?:_full)?_version\s*(?:[<>=!~]=?)\s*'([0-9][0-9.]*?)(?:\.\*)?'`)

// requiresPythonFloor finds the lower bound of a requires-python specifier
// set such as ">=3.10, <4".
var requiresPythonFloor = regexp.MustCompile(`>=?\s*([0-9][0-9.]*)`)

// fallbackPythonVersion is used when the lockfile says nothing at all about
// Python versions, which means every supported one resolves the same graph
// and the choice only names the wheels hashes are taken from.
const fallbackPythonVersion = "3.13"

// defaultPythonVersion picks the version an extraction targets when the
// caller states none: the newest version the lock's resolution forked over,
// so the default describes what installing on a current interpreter gets.
// A lock that never forked over Python falls back to the floor of
// requires-python: every version it supports sees the same graph.
func defaultPythonVersion(lock *Lockfile) string {
	newest := ""
	var newestParsed *Version
	for _, marker := range lock.ResolutionMarkers {
		for _, m := range pythonVersionLiterals.FindAllStringSubmatch(marker, -1) {
			literal := m[1]
			parsed, err := ParseVersion(literal)
			if err != nil || len(parsed.Release) < 2 {
				continue
			}
			if newestParsed == nil || parsed.Compare(newestParsed) > 0 {
				newest, newestParsed = literal, parsed
			}
		}
	}
	if newest != "" {
		return newest
	}

	if m := requiresPythonFloor.FindStringSubmatch(lock.RequiresPython); m != nil {
		if parsed, err := ParseVersion(m[1]); err == nil && len(parsed.Release) >= 2 {
			return m[1]
		}
	}
	return fallbackPythonVersion
}

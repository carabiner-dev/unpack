// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// FindCodeBases locates Python codebases by their lockfiles.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	locations := map[string]bool{}
	for _, lockfile := range []string{"uv.lock", "poetry.lock", "requirements.txt"} {
		found, err := index.FindFileLocations(lockfile)
		if err != nil {
			return nil, err
		}
		for _, dir := range found {
			locations[dir] = true
		}
	}
	dirs := make([]string, 0, len(locations))
	for dir := range locations {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// Extract builds the dependency graph the target environment sees, from
// whichever lockfile the codebase has. A project migrating between tools
// may carry both; uv.lock wins, being the one uv keeps current.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	switch {
	case fileExists(filepath.Join(workDir, "uv.lock")):
		return d.extractUv(workDir, opts)
	case fileExists(filepath.Join(workDir, "poetry.lock")):
		return d.extractPoetry(workDir, opts)
	case fileExists(filepath.Join(workDir, "requirements.txt")):
		return d.extractRequirements(workDir, opts)
	default:
		return nil, fmt.Errorf("no supported Python lockfile in %s", workDir)
	}
}

// extractUv builds the graph from a uv.lock, which is self-contained.
func (d *Decomposer) extractUv(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	lock, err := ReadLockfile(filepath.Join(workDir, "uv.lock"))
	if err != nil {
		return nil, err
	}

	dOpts := d.getOptions(opts)
	env, err := d.environment(dOpts, opts, defaultPythonVersion(lock))
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
		NewPyPIClient(dOpts.Concurrency).enrichNodes(tb.nodes, tb.enrichable)
	}
	return nl, nil
}

// extractPoetry builds the graph from a poetry.lock and the manifest next
// to it, which carries what the lock does not: the project's identity and
// its direct dependencies.
func (d *Decomposer) extractPoetry(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	lock, err := ReadPoetryLockfile(filepath.Join(workDir, "poetry.lock"))
	if err != nil {
		return nil, err
	}
	manifest, err := ReadPyProject(filepath.Join(workDir, "pyproject.toml"))
	if err != nil {
		return nil, err
	}

	dOpts := d.getOptions(opts)
	env, err := d.environment(dOpts, opts, poetryDefaultPythonVersion(lock))
	if err != nil {
		return nil, err
	}

	// Poetry states membership in a root extra as an extra == marker on
	// the extra's packages, so enabling the extras is an environment
	// matter, settled before any walk.
	if opts.IncludeOptional {
		extras, err := manifest.ExtraDependencies()
		if err != nil {
			return nil, err
		}
		env.Extras = sortedGroupNames(extras)
	}

	pb := newPoetryBuilder(lock, manifest, env, opts)
	nl, err := pb.build()
	if err != nil {
		return nil, err
	}

	if opts.Networking >= api.NetworkEssential {
		NewPyPIClient(dOpts.Concurrency).enrichNodes(pb.nodes, pb.enrichable)
	}
	return nl, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
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
func (d *Decomposer) environment(dOpts *Options, opts *api.DecomposerOptions, defaultVersion string) (*Environment, error) {
	platform := dOpts.Platform
	if platform == "" && opts != nil {
		platform = opts.Platform
	}
	goos, goarch, _ := strings.Cut(platform, "/")

	pythonVersion := dOpts.PythonVersion
	if pythonVersion == "" {
		pythonVersion = defaultVersion
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

	if version := pythonFloor(lock.RequiresPython); version != "" {
		return version
	}
	return fallbackPythonVersion
}

// poetryDefaultPythonVersion picks the version a Poetry extraction targets
// when the caller states none. A poetry.lock resolves one version per
// package rather than forking, so every supported Python sees the same
// graph and the floor of the lock's python constraint serves.
func poetryDefaultPythonVersion(lock *PoetryLockfile) string {
	if version := pythonFloor(lock.Metadata.PythonVersions); version != "" {
		return version
	}
	return fallbackPythonVersion
}

// pythonFloor reads the lower bound out of a python version constraint such
// as ">=3.10, <4".
func pythonFloor(constraint string) string {
	m := requiresPythonFloor.FindStringSubmatch(constraint)
	if m == nil {
		return ""
	}
	if parsed, err := ParseVersion(m[1]); err == nil && len(parsed.Release) >= 2 {
		return m[1]
	}
	return ""
}

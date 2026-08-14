// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package ruby implements dependency extraction for Ruby codebases managed
// by Bundler. The lockfile carries the resolved graph inline — every spec
// lists its dependencies — and, from Bundler 2.6 with checksums enabled,
// the sha256 of every artifact. What it does not carry is groups: the
// Gemfile is executable Ruby, so the lock only knows which gems are direct,
// not which of those are development-only.
package ruby

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GemLockfile is a parsed Gemfile.lock.
type GemLockfile struct {
	// Sources are the lock's spec blocks: the registry (GEM), git
	// repositories (GIT) and local paths (PATH), each holding the specs
	// resolved from it.
	Sources []*GemSource

	// Platforms are the platforms the lock resolves for.
	Platforms []string

	// Dependencies are the direct requirements (the DEPENDENCIES
	// section): every gem the Gemfile names, whatever its group.
	Dependencies []string

	// Checksums maps "name version[-platform]" to the artifact's sha256,
	// present when the lock was written with checksums (Bundler 2.6+).
	Checksums map[string]string

	// BundledWith is the Bundler version that wrote the lock.
	BundledWith string
}

// GemSource is one spec block.
type GemSource struct {
	// Type is "gem", "git" or "path".
	Type string

	// Remote is the registry URL, repository URL or local path.
	Remote string

	// Revision, Tag and Branch pin a git source; Revision is the exact
	// commit.
	Revision string
	Tag      string
	Branch   string

	Specs []*GemSpec
}

// GemSpec is one resolved gem.
type GemSpec struct {
	Name    string
	Version string

	// Platform is the variant's platform ("x86_64-linux-gnu"), empty for
	// the pure-Ruby variant. The same gem and version may appear once per
	// platform the lock covers.
	Platform string

	// Dependencies are the names the spec depends on; the lock resolves a
	// name to exactly one version, so names are edges.
	Dependencies []string

	// Source points back at the block the spec came from.
	Source *GemSource
}

// ParseGemLockfile reads a Gemfile.lock document. The format is indented
// text: unindented section headers, source attributes at two spaces, specs
// at four and their dependencies at six.
func ParseGemLockfile(data []byte) (*GemLockfile, error) {
	lock := &GemLockfile{Checksums: map[string]string{}}

	var section string
	var source *GemSource
	var spec *GemSpec

	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)

		switch {
		// A section header opens a new context.
		case indent == 0:
			section = text
			source, spec = nil, nil
			switch section {
			case "GEM", "GIT", "PATH":
				source = &GemSource{Type: strings.ToLower(section)}
				lock.Sources = append(lock.Sources, source)
			}

		// Source attributes and the specs opener.
		case indent == 2 && source != nil:
			key, value, _ := strings.Cut(text, ": ")
			switch strings.TrimSuffix(key, ":") {
			case "remote":
				source.Remote = value
			case "revision":
				source.Revision = value
			case "tag":
				source.Tag = value
			case "branch":
				source.Branch = value
			}

		// A spec.
		case indent == 4 && source != nil:
			parsed, err := parseSpecLine(text)
			if err != nil {
				return nil, err
			}
			parsed.Source = source
			source.Specs = append(source.Specs, parsed)
			spec = parsed

		// A spec's dependency: the name is the edge, the constraint noise.
		case indent == 6 && spec != nil:
			name, _, _ := strings.Cut(text, " ")
			spec.Dependencies = append(spec.Dependencies, name)

		case indent == 2 && section == "PLATFORMS":
			lock.Platforms = append(lock.Platforms, text)

		case indent == 2 && section == "DEPENDENCIES":
			// A trailing ! marks a gem pinned to a git or path source;
			// the constraint in parentheses is a resolver's input.
			name, _, _ := strings.Cut(text, " ")
			lock.Dependencies = append(lock.Dependencies, strings.TrimSuffix(name, "!"))

		case indent == 2 && section == "CHECKSUMS":
			// name (version[-platform]) sha256=hex
			if name, rest, found := strings.Cut(text, " ("); found {
				if version, sum, hasSum := strings.Cut(rest, ") sha256="); hasSum {
					lock.Checksums[name+" "+version] = sum
				}
			}

		case indent >= 2 && section == "BUNDLED WITH":
			lock.BundledWith = text
		}
	}

	if len(lock.Sources) == 0 {
		return nil, fmt.Errorf("the lockfile holds no source sections")
	}
	return lock, nil
}

// ReadGemLockfile reads a Gemfile.lock from a directory.
func ReadGemLockfile(workDir string) (*GemLockfile, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "Gemfile.lock"))
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParseGemLockfile(data)
}

// parseSpecLine reads "name (version[-platform])". Gem versions contain no
// dashes — pre-releases are dotted — so the platform starts at the first
// one.
func parseSpecLine(text string) (*GemSpec, error) {
	name, rest, found := strings.Cut(text, " (")
	versioned, closed := strings.CutSuffix(rest, ")")
	if !found || !closed || name == "" {
		return nil, fmt.Errorf("unparseable lockfile spec %q", text)
	}

	spec := &GemSpec{Name: name, Version: versioned}
	if version, platform, hasPlatform := strings.Cut(versioned, "-"); hasPlatform {
		spec.Version = version
		spec.Platform = platform
	}
	return spec, nil
}

// FullVersion returns the version as the lock spells it, platform suffix
// included: the form the checksum table is keyed by.
func (s *GemSpec) FullVersion() string {
	if s.Platform == "" {
		return s.Version
	}
	return s.Version + "-" + s.Platform
}

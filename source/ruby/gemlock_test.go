// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixtures are real Bundler 2.6.9 output: simple/ locks sinatra, ffi
// and a development-group minitest with checksums and eleven added
// platforms; gitgem/ locks rake from a git tag.

func readTestLock(t *testing.T, name string) *GemLockfile {
	t.Helper()
	lock, err := ReadGemLockfile("testdata/" + name)
	require.NoError(t, err)
	return lock
}

func specsNamed(lock *GemLockfile, name string) []*GemSpec {
	found := []*GemSpec{}
	for _, source := range lock.Sources {
		for _, spec := range source.Specs {
			if spec.Name == name {
				found = append(found, spec)
			}
		}
	}
	return found
}

func TestParseGemLockfile(t *testing.T) {
	t.Parallel()

	lock := readTestLock(t, "simple")
	require.Equal(t, "2.6.9", lock.BundledWith)

	// The direct requirements, the development group's gem among them
	// unmarked: the lock does not know groups.
	require.Equal(t, []string{"ffi", "minitest", "sinatra"}, lock.Dependencies)

	// A spec's dependencies are names: sinatra's edge list.
	sinatra := specsNamed(lock, "sinatra")[0]
	require.Equal(t, []string{
		"logger", "mustermann", "rack", "rack-protection", "rack-session", "tilt",
	}, sinatra.Dependencies)
	require.Equal(t, "gem", sinatra.Source.Type)
	require.Equal(t, "https://rubygems.org/", sinatra.Source.Remote)

	// ffi resolves once per platform plus the pure-Ruby variant, each
	// with the version split from its platform suffix.
	variants := specsNamed(lock, "ffi")
	require.Len(t, variants, 11)
	platforms := map[string]bool{}
	for _, variant := range variants {
		require.Equal(t, "1.17.4", variant.Version)
		platforms[variant.Platform] = true
	}
	require.True(t, platforms[""], "the pure-Ruby variant")
	require.True(t, platforms["x86_64-linux-gnu"])
	require.True(t, platforms["arm64-darwin"])

	// The platforms section survived, including the ones bundle lock
	// added.
	require.Contains(t, lock.Platforms, "ruby")
	require.Contains(t, lock.Platforms, "arm64-darwin")
}

// TestParseGemLockfileChecksums covers the CHECKSUMS section Bundler 2.6
// writes: one sha256 per artifact, platform variants keyed apart.
func TestParseGemLockfileChecksums(t *testing.T) {
	t.Parallel()

	lock := readTestLock(t, "simple")
	require.NotEmpty(t, lock.Checksums)

	// The generic and platform artifacts hash differently.
	generic := lock.Checksums["ffi 1.17.4"]
	linux := lock.Checksums["ffi 1.17.4-x86_64-linux-gnu"]
	require.Len(t, generic, 64)
	require.Len(t, linux, 64)
	require.NotEqual(t, generic, linux)

	// The spec knows the key it is hashed under.
	for _, spec := range specsNamed(lock, "ffi") {
		require.NotEmpty(t, lock.Checksums[spec.Name+" "+spec.FullVersion()],
			"no checksum under %q", spec.Name+" "+spec.FullVersion())
	}
}

// TestParseGemLockfileGit covers a gem locked from a repository: the
// source carries the remote, the tag asked for and the commit it resolved
// to, and the dependency is marked pinned in DEPENDENCIES.
func TestParseGemLockfileGit(t *testing.T) {
	t.Parallel()

	lock := readTestLock(t, "gitgem")

	rake := specsNamed(lock, "rake")[0]
	require.Equal(t, "git", rake.Source.Type)
	require.Equal(t, "https://github.com/ruby/rake", rake.Source.Remote)
	require.Equal(t, "1f0aa1682c53b756393c1eea2c3e7a921cbde9f4", rake.Source.Revision)
	require.Equal(t, "v13.2.1", rake.Source.Tag)

	// The ! marker is Bundler's, not part of the name.
	require.Equal(t, []string{"rake"}, lock.Dependencies)

	// An empty GEM section parses as a source with no specs.
	for _, source := range lock.Sources {
		if source.Type == "gem" {
			require.Empty(t, source.Specs)
		}
	}
}

func TestParseGemLockfileRejects(t *testing.T) {
	t.Parallel()

	for name, doc := range map[string]string{
		"no sections":      "just some text\n",
		"a malformed spec": "GEM\n  specs:\n    not a spec line (\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseGemLockfile([]byte(doc))
			require.Error(t, err)
		})
	}

	_, err := ReadGemLockfile("testdata/absent")
	require.Error(t, err)
}

// TestParseSpecLinePlatforms pins the version-platform split: gem versions
// are dotted, never dashed, so the platform starts at the first dash —
// including platforms that carry dashes of their own.
func TestParseSpecLinePlatforms(t *testing.T) {
	t.Parallel()

	for line, expected := range map[string]GemSpec{
		"rake (13.2.1)":                              {Name: "rake", Version: "13.2.1"},
		"ffi (1.17.4-x86_64-linux-gnu)":              {Name: "ffi", Version: "1.17.4", Platform: "x86_64-linux-gnu"},
		"nokogiri (1.15.4-arm64-darwin)":             {Name: "nokogiri", Version: "1.15.4", Platform: "arm64-darwin"},
		"rails (7.1.0.beta1)":                        {Name: "rails", Version: "7.1.0.beta1"},
		"sorbet-static (0.5.11142-universal-darwin)": {Name: "sorbet-static", Version: "0.5.11142", Platform: "universal-darwin"},
	} {
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			spec, err := parseSpecLine(strings.TrimSpace(line))
			require.NoError(t, err)
			require.Equal(t, expected.Name, spec.Name)
			require.Equal(t, expected.Version, spec.Version)
			require.Equal(t, expected.Platform, spec.Platform)
		})
	}
}

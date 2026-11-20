// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pkgconf

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConformsToPkgconf holds the parser to pkgconf itself, on the
// pkg-config files installed on this machine: for each, the version and
// the two classic dependency lists must be what pkgconf reads.
//
// It needs pkgconf and is skipped without it, and in short mode: it reads
// whatever the machine has.
func TestConformsToPkgconf(t *testing.T) {
	if testing.Short() {
		t.Skip("reads the pkg-config files of the machine")
	}
	tool, err := exec.LookPath("pkgconf")
	if err != nil {
		t.Skip("pkgconf is not installed")
	}

	files := []string{}
	for _, dir := range []string{"/usr/lib64/pkgconfig", "/usr/lib/pkgconfig", "/usr/share/pkgconfig", "/usr/lib/x86_64-linux-gnu/pkgconfig"} {
		found, _ := filepath.Glob(filepath.Join(dir, "*.pc")) //nolint:errcheck // the pattern is fixed
		files = append(files, found...)
	}
	if len(files) == 0 {
		t.Skip("no pkg-config files installed")
	}

	// pkgconf prints a dependency list one entry a line, as
	// "name op version" or "name".
	ask := func(file, flag string) []string {
		cmd := exec.CommandContext(t.Context(), tool, flag, file) //nolint:gosec // a fixed tool on installed files
		cmd.Env = append(os.Environ(), "PKG_CONFIG_MAXIMUM_TRAVERSE_DEPTH=1")
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		lines := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line = strings.Join(strings.Fields(line), " "); line != "" {
				lines = append(lines, line)
			}
		}
		sort.Strings(lines)
		return lines
	}
	render := func(deps []Dependency) []string {
		lines := make([]string, 0, len(deps))
		for _, dep := range deps {
			line := dep.Name
			if dep.Operator != "" {
				line += " " + dep.Operator + " " + dep.Version
			}
			lines = append(lines, line)
		}
		sort.Strings(lines)
		return lines
	}

	checked := 0
	for _, path := range files {
		version := ask(path, "--modversion")
		if len(version) != 1 {
			// pkgconf will not load it: a dependency that is not
			// installed, most often.
			continue
		}
		file, err := ReadFile(path)
		require.NoError(t, err)
		require.Empty(t, file.Unresolved, path)
		require.True(t, file.Valid(), "%s: pkgconf loads it, missing %v", path, file.Missing())
		require.Equal(t, version[0], file.Version, path)
		require.ElementsMatch(t, ask(path, "--print-requires"), render(file.Requires), path)
		require.ElementsMatch(t, ask(path, "--print-requires-private"),
			render(append(file.RequiresPrivate, file.RequiresInternal...)), path)
		checked++
	}
	t.Logf("%d of %d installed pkg-config files agree with pkgconf", checked, len(files))
	require.NotZero(t, checked)
}

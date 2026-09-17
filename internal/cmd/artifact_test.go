// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// artifactDir builds a directory holding a Go executable (a copy of the
// test binary) next to a file that is no artifact, and returns its path.
func artifactDir(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	bin, err := os.ReadFile(exe)
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tool"), bin, 0o600)) //nolint:gosec // a temp dir
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README"), []byte("not an artifact\n"), 0o600))
	return dir
}

// runArtifact runs the artifact subcommand with the given arguments.
func runArtifact(t *testing.T, args ...string) error {
	t.Helper()
	commandLineOpts.logLevel = "info"
	root := &cobra.Command{Use: "test"}
	addArtifact(root)
	root.SetArgs(append([]string{"artifact"}, args...))
	root.SetErr(io.Discard)
	root.SetOut(io.Discard)
	return root.Execute()
}

// TestArtifactCommandSPDX runs the artifact subcommand end to end on a Go
// executable and writes an SPDX SBOM to a file.
func TestArtifactCommandSPDX(t *testing.T) {
	dir := artifactDir(t)
	outPath := filepath.Join(t.TempDir(), "artifact.spdx.json")

	require.NoError(t, runArtifact(t,
		"--format", "spdx", "--networking", "disabled", "--output", outPath, filepath.Join(dir, "tool"),
	))

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "SPDX-2.3", doc["spdxVersion"])

	out := string(data)
	assert.Contains(t, out, `"tool"`, "the file node carries the artifact name")
	assert.Contains(t, out, "pkg:golang/github.com/carabiner-dev/unpack")
	assert.Contains(t, out, "pkg:golang/github.com/google/uuid@v1.6.0")
	assert.Contains(t, out, "pkg:golang/stdlib@")
}

// TestArtifactCommandDirectory scans a directory: the executable is found,
// the other file is skipped.
func TestArtifactCommandDirectory(t *testing.T) {
	dir := artifactDir(t)
	outPath := filepath.Join(t.TempDir(), "artifact.spdx.json")

	require.NoError(t, runArtifact(t, "-f", "spdx", "--networking", "disabled", "-o", outPath, dir))

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	out := string(data)
	assert.Contains(t, out, `"tool"`)
	assert.NotContains(t, out, "README")
	assert.Contains(t, out, "pkg:golang/github.com/carabiner-dev/unpack")
}

func TestArtifactCommandNotAnArtifact(t *testing.T) {
	dir := artifactDir(t)
	err := runArtifact(t, "-f", "spdx", "--networking", "disabled", filepath.Join(dir, "README"))
	require.ErrorContains(t, err, "not a recognized artifact")
}

func TestArtifactCommandSkip(t *testing.T) {
	dir := artifactDir(t)
	err := runArtifact(t, "-f", "spdx", "--networking", "disabled", "--skip-artifact", "gobinary", filepath.Join(dir, "tool"))
	require.ErrorContains(t, err, "not a recognized artifact")
}

func TestArtifactCommandErrors(t *testing.T) {
	require.Error(t, runArtifact(t), "the path is required")
	require.ErrorContains(t, runArtifact(t, "/nonexistent/binary"), "reading artifact path")
	require.ErrorContains(t, runArtifact(t, "-f", "yaml", "/nonexistent/binary"), "invalid format")
	require.ErrorContains(t, runArtifact(t, "--networking", "maybe", "/nonexistent/binary"), "invalid networking level")
}

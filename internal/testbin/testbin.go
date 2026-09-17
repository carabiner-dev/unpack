// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package testbin builds a Go executable for tests that need one with build
// information in it. The test binary itself is not a reliable stand-in:
// before Go 1.27 the go command generated a test binary's build information
// before wiring up the test main's imports, so the module list in it came
// out empty (cmd/go/internal/load/test.go regenerates it after the imports
// since 1.27). A decomposer reading such a binary finds no dependencies.
package testbin

import (
	"debug/buildinfo"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

// Package is the import path of the fixture program.
const Package = "github.com/carabiner-dev/unpack/internal/testbin/fixture"

// Build compiles the fixture program into a temporary directory and returns
// the path of the executable and the build information it carries. The
// build runs with VCS stamping off, so the main module is always (devel)
// and the result does not depend on the state of the checkout.
func Build(t *testing.T) (string, *debug.BuildInfo) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "resolving the testbin package directory")

	out := filepath.Join(t.TempDir(), "fixture")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-buildvcs=false", "-o", out, Package) //nolint:gosec // fixed arguments
	cmd.Dir = filepath.Dir(thisFile)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "building the fixture program:\n%s", output)

	info, err := buildinfo.ReadFile(out)
	require.NoError(t, err)
	return out, info
}

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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Package is the import path of the fixture program.
const Package = "github.com/carabiner-dev/unpack/internal/testbin/fixture"

// fixture is built once per test binary and shared by all its tests.
var fixture struct {
	once sync.Once
	path string
	info *debug.BuildInfo
	err  error
}

// Build returns the path of the fixture executable and the build
// information it carries, compiling it the first time a test of the
// package asks for it. Every test gets the same executable, so tests must
// treat it as read-only: copy it to change it.
//
// The build runs with VCS stamping off, so the main module is always
// (devel) and the result does not depend on the state of the checkout.
// It is not trimmed (-trimpath) so it reuses the packages the go command
// already compiled for the test binary instead of compiling them again.
// The executable lives in a directory of its own in the system temporary
// directory, which outlives the tests that share it and is not removed.
func Build(t *testing.T) (string, *debug.BuildInfo) {
	t.Helper()
	fixture.once.Do(func() {
		fixture.path, fixture.info, fixture.err = build()
	})
	require.NoError(t, fixture.err)
	return fixture.path, fixture.info
}

func build() (string, *debug.BuildInfo, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", nil, errors.New("resolving the testbin package directory")
	}

	dir, err := os.MkdirTemp("", "unpack-testbin-")
	if err != nil {
		return "", nil, fmt.Errorf("creating the fixture directory: %w", err)
	}
	out := filepath.Join(dir, "fixture")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}

	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, Package) //nolint:gosec,noctx // fixed arguments; shared by every test, no one test's context applies
	cmd.Dir = filepath.Dir(thisFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("building the fixture program: %w\n%s", err, output)
	}

	info, err := buildinfo.ReadFile(out)
	if err != nil {
		return "", nil, fmt.Errorf("reading the fixture build information: %w", err)
	}
	return out, info, nil
}

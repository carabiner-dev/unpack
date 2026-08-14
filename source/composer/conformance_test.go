// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// composerOracleImage runs the conformance oracle. Composer show --locked
// answers from the lockfile alone, with a direct-dependency flag per
// package, so the same lock the unit tests read is read back by the tool
// that wrote it. Runs in Docker like the Maven oracle; without Docker the
// test skips, and under UNPACK_FORCE_TESTS it fails instead.
const composerOracleImage = "composer:2"

// TestCompareWithComposerShow holds the extraction to composer's own
// reading of the lock: the package set, and which of them are direct.
func TestCompareWithComposerShow(t *testing.T) {
	t.Parallel()
	requireDocker(t)

	dir, err := filepath.Abs("testdata/simple")
	require.NoError(t, err)
	out, err := command.New("docker",
		"run", "--rm", "-v", dir+":/app:ro", "-w", "/app", composerOracleImage,
		"show", "--locked", "--format=json", "--ignore-platform-reqs",
	).RunSuccessOutput()
	if err != nil {
		// Docker being present does not mean it can run this image: the
		// Windows runners' Docker speaks Windows containers only, and
		// composer:2 has no Windows build. Only Linux is held to the
		// oracle; elsewhere a run failure is a skip, as the Maven
		// conformance test treats it.
		if os.Getenv("UNPACK_FORCE_TESTS") != "" && runtime.GOOS == "linux" {
			t.Fatalf("running the oracle: %v", err)
		}
		t.Skipf("skipping: the oracle did not run (%v)", err)
	}

	oracle := parseComposerShow(t, out.Output())

	// show --locked lists the whole lock, dev partition included.
	opts := &api.DecomposerOptions{IncludeDev: true, WorkDir: "testdata/simple"}
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	roots := map[string]bool{}
	for _, id := range nl.GetRootElements() {
		roots[id] = true
	}
	byID := map[string]*sbom.Node{}
	set := []string{}
	for _, n := range nl.GetNodes() {
		byID[n.GetId()] = n
		if !roots[n.GetId()] {
			set = append(set, n.GetName()+"@"+n.GetVersion())
		}
	}
	oracleSet := make([]string, 0, len(oracle))
	for _, pkg := range oracle {
		oracleSet = append(oracleSet, pkg.Name+"@"+pkg.Version)
	}
	require.ElementsMatch(t, oracleSet, set, "the packages disagree with composer show")

	// The oracle flags the direct dependencies; ours are the targets of
	// the root's edges.
	direct := map[string]bool{}
	for _, e := range nl.GetEdges() {
		if !roots[e.GetFrom()] {
			continue
		}
		for _, to := range e.GetTo() {
			direct[byID[to].GetName()] = true
		}
	}
	oracleDirect := map[string]bool{}
	for _, pkg := range oracle {
		if pkg.Direct {
			oracleDirect[pkg.Name] = true
		}
	}
	require.Equal(t, oracleDirect, direct, "the direct dependencies disagree with composer show")
}

// composerShowPackage is one entry of composer show --locked.
type composerShowPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Direct  bool   `json:"direct-dependency"`
}

// parseComposerShow reads the oracle's output, which may carry warnings
// ahead of the JSON.
func parseComposerShow(t *testing.T, out string) []composerShowPackage {
	t.Helper()
	start := strings.Index(out, "{")
	require.GreaterOrEqual(t, start, 0, "no JSON in the oracle output")

	var parsed struct {
		Locked []composerShowPackage `json:"locked"`
	}
	require.NoError(t, json.Unmarshal([]byte(out[start:]), &parsed))
	require.NotEmpty(t, parsed.Locked)
	return parsed.Locked
}

// requireDocker skips the test when Docker is not available to run the
// oracle with, and fails instead under UNPACK_FORCE_TESTS on Linux, where
// CI is expected to have it.
func requireDocker(t *testing.T) {
	t.Helper()
	if err := command.New("docker", "version").RunSilentSuccess(); err == nil {
		return
	}
	if os.Getenv("UNPACK_FORCE_TESTS") != "" && runtime.GOOS == "linux" {
		t.Fatal("docker is not available and UNPACK_FORCE_TESTS is set")
	}
	t.Skip("skipping: docker is not available to run the oracle")
}

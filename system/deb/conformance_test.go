// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

const (
	// debianDockerImage is the container image whose dpkg database the
	// conformance test extracts and compares against dpkg-query's own view.
	debianDockerImage = "debian:stable-slim"
)

// TestCompareWithDpkgQuery verifies our dpkg extraction matches dpkg's own
// view of the system. It pulls the dpkg database out of a Debian container
// and compares the resulting NodeList against `dpkg-query -W` run inside the
// same image.
//
// Set UNPACK_FORCE_TESTS=1 to fail instead of skip when Docker is not available.
func TestCompareWithDpkgQuery(t *testing.T) {
	t.Parallel()

	// Docker is only reliably available on Linux CI runners, so only force
	// the test there. macOS and Windows runners don't ship Docker.
	forceTests := os.Getenv("UNPACK_FORCE_TESTS") != "" && runtime.GOOS == "linux"

	// Check if Docker is available
	if err := command.New("docker", "version").RunSilentSuccess(); err != nil {
		if forceTests {
			t.Fatal("docker not available and UNPACK_FORCE_TESTS is set")
		}
		t.Skip("docker not available, skipping conformance test")
	}

	// Ask dpkg itself what is installed.
	dpkgPackages := runDpkgQuery(t, forceTests)
	if dpkgPackages == nil {
		return
	}
	require.NotEmpty(t, dpkgPackages, "dpkg-query returned no installed packages")
	t.Logf("dpkg-query reports %d installed packages", len(dpkgPackages))

	// Extract the dpkg database and os-release into a local system root and
	// run our decomposer over it.
	sysroot := copyDpkgDB(t, forceTests)
	if sysroot == "" {
		return
	}

	d := New()
	nl, err := d.Extract(&api.DecomposerOptions{WorkDir: sysroot})
	require.NoError(t, err)
	require.NotNil(t, nl, "no dpkg database found in the extracted system root")

	ours := map[string]string{}
	for _, n := range nl.GetNodes() {
		ours[n.GetName()] = n.GetVersion()
	}
	t.Logf("we extracted %d packages", len(ours))

	// Every package dpkg reports must be in our output with the same version,
	// and we must not invent extras.
	for name, version := range dpkgPackages {
		if assert.Contains(t, ours, name) {
			assert.Equal(t, version, ours[name], "version mismatch for %s", name)
		}
	}
	assert.Len(t, ours, len(dpkgPackages))
}

// runDpkgQuery lists the installed packages of the conformance image as
// dpkg-query sees them, returning name → version.
func runDpkgQuery(t *testing.T, forceTests bool) map[string]string {
	t.Helper()

	cmd := command.New(
		"docker", "run", "--rm", debianDockerImage,
		"dpkg-query", "-W",
		"-f", `${Package}\t${Version}\t${db:Status-Status}\n`,
	)
	output, err := cmd.RunSuccessOutput()
	if err != nil {
		if forceTests {
			t.Fatalf("dpkg-query failed: %v\n%s", err, output.Output())
		}
		t.Skipf("dpkg-query failed (may need network): %v", err)
		return nil
	}

	pkgs := map[string]string{}
	for line := range strings.SplitSeq(output.Output(), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[2] != "installed" {
			continue
		}
		pkgs[fields[0]] = fields[1]
	}
	return pkgs
}

// copyDpkgDB extracts the dpkg status file and os-release from the
// conformance image into a temporary directory shaped like a system root.
func copyDpkgDB(t *testing.T, forceTests bool) string {
	t.Helper()

	output, err := command.New("docker", "create", debianDockerImage).RunSuccessOutput()
	if err != nil {
		if forceTests {
			t.Fatalf("creating container: %v\n%s", err, output.Output())
		}
		t.Skipf("creating container failed (may need network): %v", err)
		return ""
	}
	ctr := strings.TrimSpace(output.Output())
	t.Cleanup(func() {
		//nolint:errcheck,gosec // best-effort container cleanup
		command.New("docker", "rm", ctr).RunSilentSuccess()
	})

	sysroot := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(sysroot, "var/lib/dpkg"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(sysroot, "etc"), 0o750))

	for _, cp := range [][2]string{
		{ctr + ":/var/lib/dpkg/status", filepath.Join(sysroot, "var/lib/dpkg/status")},
		// -L follows the os-release symlink into usr/lib.
		{ctr + ":/etc/os-release", filepath.Join(sysroot, "etc/os-release")},
	} {
		require.NoError(t,
			command.New("docker", "cp", "-L", cp[0], cp[1]).RunSilentSuccess(),
			"copying %s out of the container", cp[0],
		)
	}
	return sysroot
}

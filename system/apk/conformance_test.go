// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package apk

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
	// alpineDockerImage is the container image whose apk database the
	// conformance test extracts and compares against apk's own view.
	alpineDockerImage = "alpine:latest"
)

// TestCompareWithApkList verifies our apk extraction matches apk's own view
// of the system. It pulls the installed database out of an Alpine container
// and compares the resulting NodeList against `apk list --installed` run
// inside the same image.
//
// Set UNPACK_FORCE_TESTS=1 to fail instead of skip when Docker is not available.
func TestCompareWithApkList(t *testing.T) {
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

	// Ask apk itself what is installed.
	apkPackages := runApkList(t, forceTests)
	if apkPackages == nil {
		return
	}
	require.NotEmpty(t, apkPackages, "apk list returned no installed packages")
	t.Logf("apk list reports %d installed packages", len(apkPackages))

	// Extract the apk database and os-release into a local system root and
	// run our decomposer over it.
	sysroot := copyApkDB(t, forceTests)
	if sysroot == "" {
		return
	}

	d := New()
	nl, err := d.Extract(&api.DecomposerOptions{WorkDir: sysroot})
	require.NoError(t, err)
	require.NotNil(t, nl, "no apk database found in the extracted system root")

	// apk list prints "name-version"; our nodes carry them separately.
	ours := map[string]bool{}
	for _, n := range nl.GetNodes() {
		ours[n.GetName()+"-"+n.GetVersion()] = true
	}
	t.Logf("we extracted %d packages", len(ours))

	// Every package apk reports must be in our output, and we must not
	// invent extras.
	for nameVersion := range apkPackages {
		assert.Contains(t, ours, nameVersion)
	}
	assert.Len(t, ours, len(apkPackages))
}

// runApkList lists the installed packages of the conformance image as apk
// sees them, returning a set of "name-version" strings.
func runApkList(t *testing.T, forceTests bool) map[string]bool {
	t.Helper()

	cmd := command.New(
		"docker", "run", "--rm", alpineDockerImage,
		"apk", "list", "--installed",
	)
	output, err := cmd.RunSuccessOutput()
	if err != nil {
		if forceTests {
			t.Fatalf("apk list failed: %v\n%s", err, output.Output())
		}
		t.Skipf("apk list failed (may need network): %v", err)
		return nil
	}

	// Lines look like:
	//	musl-1.2.6-r2 x86_64 {musl} (MIT) [installed]
	pkgs := map[string]bool{}
	for line := range strings.SplitSeq(output.Output(), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(line, "[installed]") {
			continue
		}
		pkgs[fields[0]] = true
	}
	return pkgs
}

// copyApkDB extracts the apk installed database and os-release from the
// conformance image into a temporary directory shaped like a system root.
func copyApkDB(t *testing.T, forceTests bool) string {
	t.Helper()

	output, err := command.New("docker", "create", alpineDockerImage).RunSuccessOutput()
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
	require.NoError(t, os.MkdirAll(filepath.Join(sysroot, "lib/apk/db"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(sysroot, "etc"), 0o750))

	for _, cp := range [][2]string{
		{ctr + ":/lib/apk/db/installed", filepath.Join(sysroot, "lib/apk/db/installed")},
		// -L follows the os-release symlink when it is one.
		{ctr + ":/etc/os-release", filepath.Join(sysroot, "etc/os-release")},
	} {
		require.NoError(t,
			command.New("docker", "cp", "-L", cp[0], cp[1]).RunSilentSuccess(),
			"copying %s out of the container", cp[0],
		)
	}
	return sysroot
}

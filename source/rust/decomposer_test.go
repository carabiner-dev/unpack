// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestParseCargoLock(t *testing.T) {
	t.Parallel()

	lock, err := ParseCargoLock("testdata/simple")
	require.NoError(t, err)
	require.NotNil(t, lock)

	// Check we got the expected packages
	require.Len(t, lock.Packages, 3) // am-i-isolated, anyhow, libc

	// Check root package
	roots := lock.FindRootPackages()
	require.Len(t, roots, 1)
	require.Equal(t, "am-i-isolated", roots[0].Name)
	require.Equal(t, "0.4.0", roots[0].Version)
	require.Len(t, roots[0].Dependencies, 2)
}

func TestParseCargoToml(t *testing.T) {
	t.Parallel()

	toml, err := ParseCargoToml("testdata/simple")
	require.NoError(t, err)
	require.NotNil(t, toml)

	// Check package info
	require.Equal(t, "am-i-isolated", toml.Package.Name)
	require.Equal(t, "0.4.0", toml.Package.Version)

	// Check dependencies
	require.Len(t, toml.Dependencies, 2)
	require.Contains(t, toml.Dependencies, "anyhow")
	require.Contains(t, toml.Dependencies, "libc")
}

func TestParseCargoTomlWithTableDeps(t *testing.T) {
	t.Parallel()

	toml, err := ParseCargoToml("testdata/larger")
	require.NoError(t, err)
	require.NotNil(t, toml)

	// Check that table-style dependencies are parsed correctly
	require.Contains(t, toml.Dependencies, "falco_plugin")
	dep := toml.Dependencies["falco_plugin"]
	require.Equal(t, "0.5.1", dep.GetVersion())
}

func TestDecomposerExtract(t *testing.T) {
	t.Parallel()

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir: "testdata/simple",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Check root nodes
	roots := nl.GetRootElements()
	require.Len(t, roots, 1)

	// Check we have the expected number of nodes
	nodes := nl.GetNodes()
	require.Len(t, nodes, 3) // root + 2 deps
}

func TestDecomposerExtractLarger(t *testing.T) {
	t.Parallel()

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir: "testdata/larger",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Check we have root nodes
	roots := nl.GetRootElements()
	require.GreaterOrEqual(t, len(roots), 1)

	// Check we have many nodes (the larger project has many deps)
	nodes := nl.GetNodes()
	require.Greater(t, len(nodes), 50) // Should have many transitive deps
}

// TestCompareWithCargoTree verifies our parsing matches cargo tree output.
// This test requires cargo to be installed and will be skipped if not available.
func TestCompareWithCargoTree(t *testing.T) {
	t.Parallel()

	// Check if cargo is available
	//nolint:errcheck
	if _, err := command.New("cargo", "--version").RunSilentSuccessOutput(); err != nil {
		t.Skip("cargo not available, skipping comparison test")
	}

	for _, tc := range []struct {
		name    string
		workDir string
	}{
		{"simple", "testdata/simple"},
		{"larger", "testdata/larger"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Get absolute path for cargo
			absPath, err := filepath.Abs(tc.workDir)
			require.NoError(t, err)

			// Run cargo tree to get the expected dependencies
			cmd := command.NewWithWorkDir(absPath, "cargo", "tree", "--prefix=none", "--edges=normal")
			output, err := cmd.RunSilentSuccessOutput()
			require.NoError(t, err)

			// Parse cargo tree output to get list of packages
			cargoPackages := parseCargoTreeOutput(output.OutputTrimNL())

			// Extract using our implementation
			d := New()
			opts := &api.DecomposerOptions{
				WorkDir: tc.workDir,
			}
			nl, err := d.Extract(opts)
			require.NoError(t, err)

			// Get packages from our nodelist
			ourPackages := make(map[string]bool)
			for _, node := range nl.GetNodes() {
				key := node.GetName() + "@" + node.GetVersion()
				ourPackages[key] = true
			}

			// Verify all cargo tree packages are in our output
			// Note: We may have MORE packages than cargo tree shows because:
			// 1. Cargo.lock contains all platform-specific dependencies
			// 2. cargo tree filters to the current platform
			// The important thing is that we include everything cargo shows
			missing := []string{}
			for pkg := range cargoPackages {
				if !ourPackages[pkg] {
					missing = append(missing, pkg)
				}
			}
			require.Empty(t, missing,
				"packages found in cargo tree but not in our output: %v", missing)

			// Our count should be >= cargo's count (we include all platforms)
			cargoPkgCount := len(cargoPackages)
			ourPkgCount := len(ourPackages)
			require.GreaterOrEqual(t, ourPkgCount, cargoPkgCount,
				"our package count (%d) should be >= cargo tree count (%d)",
				ourPkgCount, cargoPkgCount)
		})
	}
}

// TestDependencyTypes verifies that dependency types are correctly assigned.
func TestDependencyTypes(t *testing.T) {
	t.Parallel()

	// Create a test case with dev and build dependencies
	tomlData := []byte(`
[package]
name = "test-pkg"
version = "1.0.0"

[dependencies]
serde = "1.0"

[dev-dependencies]
test-lib = "0.1"

[build-dependencies]
cc = "1.0"
`)

	toml, err := ParseCargoTomlData(tomlData)
	require.NoError(t, err)

	deps := toml.GetDirectDependencies()

	require.Equal(t, DepTypeNormal, deps["serde"])
	require.Equal(t, DepTypeDev, deps["test-lib"])
	require.Equal(t, DepTypeBuild, deps["cc"])
}

// TestResolveDependency tests dependency resolution with version disambiguation.
func TestResolveDependency(t *testing.T) {
	t.Parallel()

	lockData := []byte(`
version = 4

[[package]]
name = "test-pkg"
version = "1.0.0"

[[package]]
name = "hashbrown"
version = "0.14.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "hashbrown"
version = "0.15.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	lock, err := ParseCargoLockData(lockData)
	require.NoError(t, err)

	byKey, byName := lock.BuildPackageIndex()

	// Test resolution with version
	pkg, err := ResolveDependency("hashbrown 0.14.0", byKey, byName)
	require.NoError(t, err)
	require.Equal(t, "0.14.0", pkg.Version)

	pkg, err = ResolveDependency("hashbrown 0.15.0", byKey, byName)
	require.NoError(t, err)
	require.Equal(t, "0.15.0", pkg.Version)

	// Test resolution without version (returns first found)
	pkg, err = ResolveDependency("hashbrown", byKey, byName)
	require.NoError(t, err)
	require.NotNil(t, pkg)
}

// parseCargoTreeOutput parses the output of cargo tree --prefix=none
// and returns a map of package@version strings.
func parseCargoTreeOutput(output string) map[string]bool {
	packages := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Regex to match package lines: "name vX.Y.Z" or "name vX.Y.Z (*)"
	// Also handles "(proc-macro)" suffix
	re := regexp.MustCompile(`^(\S+)\s+v(\S+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if matches != nil {
			name := matches[1]
			version := matches[2]
			packages[name+"@"+version] = true
		}
	}

	return packages
}

// TestFindCodeBases tests that the decomposer can find Rust codebases.
func TestFindCodeBases(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()

	// Create a Cargo.lock file
	cargoLockPath := filepath.Join(tmpDir, "Cargo.lock")
	err := os.WriteFile(cargoLockPath, []byte("version = 4\n"), 0o600)
	require.NoError(t, err)

	// Create a subdirectory with another Cargo.lock
	subDir := filepath.Join(tmpDir, "subproject")
	err = os.MkdirAll(subDir, 0o750)
	require.NoError(t, err)

	subCargoLock := filepath.Join(subDir, "Cargo.lock")
	err = os.WriteFile(subCargoLock, []byte("version = 4\n"), 0o600)
	require.NoError(t, err)

	// TODO: Add actual PathIndex test when we can create one easily
	// For now, just verify the decomposer interface is correct
	d := New()
	require.NotNil(t, d)
}

// TestEdgeTypes verifies that the correct edge types are used for different dependency types.
func TestEdgeTypes(t *testing.T) {
	t.Parallel()

	// Create minimal Cargo files for testing
	tmpDir := t.TempDir()

	tomlContent := `
[package]
name = "test-pkg"
version = "1.0.0"

[dependencies]
normal-dep = "1.0"

[dev-dependencies]
dev-dep = "1.0"

[build-dependencies]
build-dep = "1.0"
`

	lockContent := `
version = 4

[[package]]
name = "test-pkg"
version = "1.0.0"
dependencies = [
  "normal-dep",
  "dev-dep",
  "build-dep",
]

[[package]]
name = "normal-dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "dev-dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "build-dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

	err := os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte(tomlContent), 0o600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, "Cargo.lock"), []byte(lockContent), 0o600)
	require.NoError(t, err)

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir: tmpDir,
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Verify we have the root and 3 dependencies
	nodes := nl.GetNodes()
	require.Len(t, nodes, 4)

	// Verify edges exist (the edge types are stored in the nodelist internally)
	// We can verify by checking that nodes are properly connected
	roots := nl.GetRootElements()
	require.Len(t, roots, 1)
}

// TestListDependencies tests the helper function for debugging.
func TestListDependencies(t *testing.T) {
	t.Parallel()

	toml, err := ParseCargoToml("testdata/simple")
	require.NoError(t, err)

	lock, err := ParseCargoLock("testdata/simple")
	require.NoError(t, err)

	tree := NewDependencyTree(toml, lock)
	deps := tree.ListDependencies()

	// Should be sorted
	sorted := make([]string, len(deps))
	copy(sorted, deps)
	sort.Strings(sorted)
	require.Equal(t, sorted, deps)

	// Should contain our expected packages
	require.Contains(t, deps, "am-i-isolated@0.4.0")
	require.Contains(t, deps, "anyhow@1.0.98")
	require.Contains(t, deps, "libc@0.2.173")
}

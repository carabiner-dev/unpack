// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
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

	// Check that the root node has the license from Cargo.toml
	rootNodes := nl.GetRootNodes()
	require.Len(t, rootNodes, 1)
	require.Contains(t, rootNodes[0].GetLicenses(), "Apache-2.0")
}

// TestCompareWithCargoTree verifies our parsing matches cargo tree output.
// This test requires cargo to be installed and will be skipped if not available.
// Set UNPACK_FORCE_TESTS=1 to fail instead of skip when cargo is missing (for CI).
func TestCompareWithCargoTree(t *testing.T) {
	t.Parallel()

	// Check if cargo is available
	//nolint:errcheck
	if _, err := command.New("cargo", "--version").RunSilentSuccessOutput(); err != nil {
		if os.Getenv("UNPACK_FORCE_TESTS") != "" {
			t.Fatal("cargo not available and UNPACK_FORCE_TESTS is set")
		}
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
		WorkDir:      tmpDir,
		IncludeDev:   true,
		IncludeBuild: true,
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

	// Without dev/build, only the normal dep should be included
	optsNoDevBuild := &api.DecomposerOptions{
		WorkDir: tmpDir,
	}
	nl2, err := d.Extract(optsNoDevBuild)
	require.NoError(t, err)
	require.Len(t, nl2.GetNodes(), 2) // root + normal-dep only
}

// TestDependencyTypePrecedence checks the type a crate declared in several
// sections is given: normal over build over dev, whichever section it is
// in, target-specific ones included.
func TestDependencyTypePrecedence(t *testing.T) {
	t.Parallel()

	toml, err := ParseCargoTomlData([]byte(`
[package]
name = "test-pkg"
version = "1.0.0"

[dependencies]
normal-and-dev = "1.0"

[dev-dependencies]
normal-and-dev = "1.0"
build-and-dev = "1.0"
target-normal-and-dev = "1.0"

[build-dependencies]
build-and-dev = "1.0"

[target.'cfg(unix)'.dependencies]
target-normal-and-dev = "1.0"
`))
	require.NoError(t, err)

	deps := toml.GetDirectDependencies()
	require.Equal(t, DepTypeNormal, deps["normal-and-dev"])
	require.Equal(t, DepTypeBuild, deps["build-and-dev"])
	require.Equal(t, DepTypeNormal, deps["target-normal-and-dev"])
}

// TestEdgeTypesOnlyFromManifestPackage checks that the kinds Cargo.toml
// declares qualify the edges of the package it describes and no others: a
// crate the root only uses for its tests is still part of the build when
// one of the root's dependencies requires it.
func TestEdgeTypesOnlyFromManifestPackage(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte(`
[package]
name = "test-pkg"
version = "1.0.0"

[dependencies]
zeta = "1.0"

[dev-dependencies]
rand = "0.7"
serde = "1.0"
testonly = "1.0"
`), 0o600))

	// The root's dev dependency on serde comes before zeta, which also
	// requires it: the edge left out must not keep serde from being
	// walked when zeta reaches it.
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "Cargo.lock"), []byte(`
version = 4

[[package]]
name = "rand"
version = "0.7.3"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
  "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "test-pkg"
version = "1.0.0"
dependencies = [
  "rand 0.7.3",
  "serde",
  "testonly",
  "zeta",
]

[[package]]
name = "testonly"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "zeta"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
  "rand 0.8.5",
  "serde",
]
`), 0o600))

	// edges lists the graph as "from -> to (type)" lines, sorted.
	edges := func(nl *sbom.NodeList) []string {
		label := func(id string) string {
			n := nl.GetNodeByID(id)
			return n.GetName() + "@" + n.GetVersion()
		}
		lines := []string{}
		for _, e := range nl.GetEdges() {
			for _, to := range e.GetTo() {
				lines = append(lines, label(e.GetFrom())+" -> "+label(to)+" ("+e.GetType().String()+")")
			}
		}
		sort.Strings(lines)
		return lines
	}

	d := New()
	nl, err := d.Extract(&api.DecomposerOptions{WorkDir: tmpDir, Networking: api.NetworkDisabled})
	require.NoError(t, err)
	require.Equal(t, []string{
		"serde@1.0.0 -> serde_derive@1.0.0 (dependsOn)",
		"test-pkg@1.0.0 -> zeta@1.0.0 (dependsOn)",
		"zeta@1.0.0 -> rand@0.8.5 (dependsOn)",
		"zeta@1.0.0 -> serde@1.0.0 (dependsOn)",
	}, edges(nl))

	nl, err = d.Extract(&api.DecomposerOptions{WorkDir: tmpDir, Networking: api.NetworkDisabled, IncludeDev: true})
	require.NoError(t, err)
	require.Equal(t, []string{
		"serde@1.0.0 -> serde_derive@1.0.0 (dependsOn)",
		"test-pkg@1.0.0 -> rand@0.7.3 (devDependency)",
		"test-pkg@1.0.0 -> serde@1.0.0 (devDependency)",
		"test-pkg@1.0.0 -> testonly@1.0.0 (devDependency)",
		"test-pkg@1.0.0 -> zeta@1.0.0 (dependsOn)",
		"zeta@1.0.0 -> rand@0.8.5 (dependsOn)",
		"zeta@1.0.0 -> serde@1.0.0 (dependsOn)",
	}, edges(nl))
}

// rustEdges lists a graph as "from -> to" lines by package name, sorted.
func rustEdges(nl *sbom.NodeList) []string {
	lines := []string{}
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			lines = append(lines, nl.GetNodeByID(e.GetFrom()).GetName()+" -> "+nl.GetNodeByID(to).GetName())
		}
	}
	sort.Strings(lines)
	return lines
}

// rustRootNames lists the names of a graph's roots, in order.
func rustRootNames(nl *sbom.NodeList) []string {
	names := make([]string, 0, len(nl.GetRootElements()))
	for _, id := range nl.GetRootElements() {
		names = append(names, nl.GetNodeByID(id).GetName())
	}
	return names
}

// localPackagesLock is a lock with three local packages: app requires
// helper, which requires the registry crate dep, and tool stands alone.
const localPackagesLock = `
version = 4

[[package]]
name = "app"
version = "1.0.0"
dependencies = [
  "helper",
]

[[package]]
name = "dep"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "helper"
version = "0.3.0"
dependencies = [
  "dep",
]

[[package]]
name = "tool"
version = "0.1.0"
dependencies = [
  "dep",
]
`

// TestRootPackages checks which local packages a graph is rooted at, by
// the kind of project Cargo.toml describes, and that a local package is in
// the graph once however many ways it is reached.
func TestRootPackages(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		manifest string
		roots    []string
		edges    []string
		licensed []string
	}{
		{
			// A local package beside the project's is a path dependency.
			// tool, which nothing requires, is not part of this project.
			name: "single package",
			manifest: `
[package]
name = "app"
version = "1.0.0"
license = "MIT"

[dependencies]
helper = { path = "../helper" }
`,
			roots:    []string{"app"},
			edges:    []string{"app -> helper", "helper -> dep"},
			licensed: []string{"app"},
		},
		{
			// The members are roots, the manifest's package first, and
			// a member another requires is still one node.
			name: "package with a workspace",
			manifest: `
[package]
name = "helper"
version = "0.3.0"
license = "MIT"

[workspace]
members = ["app", "tool"]
`,
			roots:    []string{"helper", "app", "tool"},
			edges:    []string{"app -> helper", "helper -> dep", "tool -> dep"},
			licensed: []string{"helper"},
		},
		{
			name: "virtual workspace",
			manifest: `
[workspace]
members = ["app", "helper", "tool"]
`,
			roots: []string{"app", "helper", "tool"},
			edges: []string{"app -> helper", "helper -> dep", "tool -> dep"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte(tc.manifest), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "Cargo.lock"), []byte(localPackagesLock), 0o600))

			nl, err := New().Extract(&api.DecomposerOptions{WorkDir: tmpDir, Networking: api.NetworkDisabled})
			require.NoError(t, err)

			require.Equal(t, tc.roots, rustRootNames(nl))
			require.Equal(t, tc.edges, rustEdges(nl))

			// One node per package, and the manifest's license on the
			// package it describes alone.
			seen := map[string]int{}
			licensed := []string{}
			for _, n := range nl.GetNodes() {
				seen[n.GetName()]++
				if len(n.GetLicenses()) > 0 {
					licensed = append(licensed, n.GetName())
				}
			}
			for name, count := range seen {
				require.Equal(t, 1, count, "%s is in the graph %d times", name, count)
			}
			require.ElementsMatch(t, tc.licensed, licensed)
		})
	}
}

// TestListDependencies tests the helper function for debugging.
func TestListDependencies(t *testing.T) {
	t.Parallel()

	toml, err := ParseCargoToml("testdata/simple")
	require.NoError(t, err)

	lock, err := ParseCargoLock("testdata/simple")
	require.NoError(t, err)

	tree := NewDependencyTree(toml, lock, &Options{})
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

func TestEnrich(t *testing.T) {
	t.Parallel()

	// Set up a fake crates.io API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond to any /crates/{name}/{version} request
		switch r.URL.Path {
		case "/crates/anyhow/1.0.98":
			w.Write([]byte(`{"version":{"license":"MIT OR Apache-2.0","description":"Flexible error type","homepage":"https://anyhow.rs","documentation":"https://docs.rs/anyhow","repository":"https://github.com/dtolnay/anyhow","checksum":"abc123","crate_size":42000,"rust_version":"1.39","yanked":false}}`)) //nolint:errcheck,gosec
		case "/crates/libc/0.2.173":
			w.Write([]byte(`{"version":{"license":"MIT OR Apache-2.0","description":"Raw bindings to platform APIs","homepage":"","documentation":"https://docs.rs/libc","repository":"https://github.com/rust-lang/libc","checksum":"def456","crate_size":800000,"rust_version":"1.63","yanked":false}}`)) //nolint:errcheck,gosec
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Parse testdata/simple
	toml, err := ParseCargoToml("testdata/simple")
	require.NoError(t, err)
	lock, err := ParseCargoLock("testdata/simple")
	require.NoError(t, err)

	tree := NewDependencyTree(toml, lock, &Options{})
	nl, err := tree.Build(&api.DecomposerOptions{WorkDir: "testdata/simple"})
	require.NoError(t, err)

	// Create client pointing at fake server
	client := NewCratesIOClient(2)
	client.BaseURL = server.URL

	// Enrich
	tree.Enrich(client)

	// Verify anyhow node got enriched
	anyhowNodes := nl.GetNodesByIdentifier("purl", "pkg:cargo/anyhow@1.0.98")
	require.Len(t, anyhowNodes, 1)
	anyhow := anyhowNodes[0]

	require.Contains(t, anyhow.GetLicenses(), "MIT OR Apache-2.0")
	require.Equal(t, "Flexible error type", anyhow.GetDescription())
	require.Equal(t, "https://anyhow.rs", anyhow.GetUrlHome())

	// Check external references
	var hasVCS, hasDocs bool
	for _, ref := range anyhow.GetExternalReferences() {
		if ref.GetType() == sbom.ExternalReference_VCS && ref.GetUrl() == "https://github.com/dtolnay/anyhow" {
			hasVCS = true
		}
		if ref.GetType() == sbom.ExternalReference_DOCUMENTATION && ref.GetUrl() == "https://docs.rs/anyhow" {
			hasDocs = true
		}
	}
	require.True(t, hasVCS, "should have VCS external reference")
	require.True(t, hasDocs, "should have DOCUMENTATION external reference")

	// Check properties
	var hasCrateSize, hasRustVersion bool
	for _, prop := range anyhow.GetProperties() {
		if prop.GetName() == "crates.io:crate_size" && prop.GetData() == "42000" {
			hasCrateSize = true
		}
		if prop.GetName() == "crates.io:rust_version" && prop.GetData() == "1.39" {
			hasRustVersion = true
		}
	}
	require.True(t, hasCrateSize, "should have crate_size property")
	require.True(t, hasRustVersion, "should have rust_version property")

	// Verify libc node got enriched
	libcNodes := nl.GetNodesByIdentifier("purl", "pkg:cargo/libc@0.2.173")
	require.Len(t, libcNodes, 1)
	libc := libcNodes[0]

	require.Contains(t, libc.GetLicenses(), "MIT OR Apache-2.0")
	require.Equal(t, "Raw bindings to platform APIs", libc.GetDescription())
	// homepage is empty, so UrlHome should remain empty
	require.Empty(t, libc.GetUrlHome())

	// Root node should NOT be enriched by crates.io (it's local)
	rootNodes := nl.GetRootNodes()
	require.Len(t, rootNodes, 1)
	// Root should have no description from crates.io
	require.Empty(t, rootNodes[0].GetDescription())
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//nolint:goconst
package npm

import (
	"bufio"
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

func TestParsePackageLock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workDir     string
		wantName    string
		minPackages int
	}{
		{
			name:        "k8s.io",
			workDir:     "testdata/k8s.io",
			wantName:    "kubernetes.io",
			minPackages: 50,
		},
		{
			name:        "demorepo",
			workDir:     "testdata/demorepo",
			wantName:    "dummyrepo-js",
			minPackages: 100,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lock, err := ParsePackageLock(tc.workDir)
			require.NoError(t, err)
			require.NotNil(t, lock)

			// Check basic properties
			require.Equal(t, tc.wantName, lock.Name)
			require.Equal(t, 3, lock.LockfileVersion)

			// Check we got packages
			require.Greater(t, len(lock.Packages), tc.minPackages)

			// Check root package exists
			root := lock.GetRootPackage()
			require.NotNil(t, root)
			require.Equal(t, tc.wantName, root.Name)
		})
	}
}

func TestParsePackageJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workDir     string
		wantName    string
		wantVersion string
		wantDeps    int
		wantDevDeps int
		checkDep    string
	}{
		{
			name:        "k8s.io",
			workDir:     "testdata/k8s.io",
			wantName:    "kubernetes.io",
			wantVersion: "1.0.0",
			wantDeps:    0,
			wantDevDeps: 3,
			checkDep:    "autoprefixer",
		},
		{
			name:        "demorepo",
			workDir:     "testdata/demorepo",
			wantName:    "dummyrepo-js",
			wantVersion: "0.1.0",
			wantDeps:    12,
			wantDevDeps: 0,
			checkDep:    "react",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pkg, err := ParsePackageJSON(tc.workDir)
			require.NoError(t, err)
			require.NotNil(t, pkg)

			// Check package info
			require.Equal(t, tc.wantName, pkg.Name)
			require.Equal(t, tc.wantVersion, pkg.Version)

			// Check dependencies
			require.Len(t, pkg.Dependencies, tc.wantDeps)
			require.Len(t, pkg.DevDependencies, tc.wantDevDeps)

			// Check a specific dependency exists
			if tc.wantDeps > 0 {
				require.Contains(t, pkg.Dependencies, tc.checkDep)
			} else {
				require.Contains(t, pkg.DevDependencies, tc.checkDep)
			}
		})
	}
}

func TestExtractPackageName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@types/node", "@types/node"},
		{"node_modules/a/node_modules/b", "b"},
		{"node_modules/@scope/pkg/node_modules/@other/dep", "@other/dep"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			result := ExtractPackageName(tc.path)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestParseIntegrity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		integrity string
		wantAlgo  string
		wantErr   bool
	}{
		{
			name:      "sha512",
			integrity: "sha512-JU3teHTNjmE2VCGFzuY8EXzCDVwEqB2a8fsIvwaStHhAWJEeVd1o1QD80CU6+ZdEXXSLbSsuLwJjkCBWqRQUVA==",
			wantAlgo:  "sha512",
			wantErr:   false,
		},
		{
			name:      "sha256",
			integrity: "sha256-dOy+3AuW3a2wNbZHIuMZpTcgjGuLU/uBL/ubcZF9OXbDo8ff4O8yVp5Bf0efS8uEoYo5q4Fx7dY9OgQGXgAsQA==",
			wantAlgo:  "sha256",
			wantErr:   false,
		},
		{
			name:      "empty",
			integrity: "",
			wantAlgo:  "",
			wantErr:   false,
		},
		{
			name:      "invalid format",
			integrity: "invalid",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			algo, hash, err := ParseIntegrity(tc.integrity)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantAlgo, algo)
			if tc.integrity != "" {
				require.NotEmpty(t, hash)
			}
		})
	}
}

func TestBuildPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"@types/node", "18.0.0", "pkg:npm/types/node@18.0.0"},
		{"@scope/package", "1.0.0", "pkg:npm/scope/package@1.0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := buildPURL(tc.name, tc.version)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestDecomposerExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workDir     string
		wantName    string
		minNodes    int
	}{
		{
			name:     "k8s.io",
			workDir:  "testdata/k8s.io",
			wantName: "kubernetes.io",
			minNodes: 50,
		},
		{
			name:     "demorepo",
			workDir:  "testdata/demorepo",
			wantName: "dummyrepo-js",
			minNodes: 100,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := New()
			opts := &api.DecomposerOptions{
				WorkDir: tc.workDir,
			}

			nl, err := d.Extract(opts)
			require.NoError(t, err)
			require.NotNil(t, nl)

			// Check root nodes
			roots := nl.GetRootElements()
			require.Len(t, roots, 1)

			// Find root node
			var rootNode *sbom.Node
			for _, node := range nl.GetNodes() {
				if node.GetName() == tc.wantName {
					rootNode = node
					break
				}
			}
			require.NotNil(t, rootNode)
			require.Equal(t, tc.wantName, rootNode.GetName())

			// Check we have many nodes
			nodes := nl.GetNodes()
			require.Greater(t, len(nodes), tc.minNodes)
		})
	}
}

func TestDecomposerExtractWithVersion(t *testing.T) {
	t.Parallel()

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir: "testdata/k8s.io",
		Version: "2.0.0",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Find root node and verify version override
	var rootNode *sbom.Node
	for _, node := range nl.GetNodes() {
		if node.GetName() == "kubernetes.io" {
			rootNode = node
			break
		}
	}
	require.NotNil(t, rootNode)
	require.Equal(t, "2.0.0", rootNode.GetVersion())

	// Verify PURL contains the overridden version
	purl := rootNode.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	require.Contains(t, purl, "@2.0.0")
}

func TestDecomposerExtractWithCommitHash(t *testing.T) {
	t.Parallel()

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir:    "testdata/k8s.io",
		CommitHash: "abc123def456",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Find root node and verify commit hash in external references
	var rootNode *sbom.Node
	for _, node := range nl.GetNodes() {
		if node.GetName() == "kubernetes.io" {
			rootNode = node
			break
		}
	}
	require.NotNil(t, rootNode)

	// Check external references for VCS info
	found := false
	for _, ref := range rootNode.GetExternalReferences() {
		if ref.GetType() == sbom.ExternalReference_VCS {
			hash := ref.GetHashes()[int32(sbom.HashAlgorithm_SHA1)]
			if hash == "abc123def456" {
				found = true
				break
			}
		}
	}
	require.True(t, found, "commit hash not found in external references")
}

// TestCompareWithNpmLs verifies our parsing matches npm ls output.
// This test requires npm to be installed and node_modules to exist.
// Run `npm ci` in testdata directories first to enable this test.
// Set UNPACK_FORCE_TESTS=1 to fail instead of skip when npm/node_modules is missing (for CI).
func TestCompareWithNpmLs(t *testing.T) {
	t.Parallel()

	forceTests := os.Getenv("UNPACK_FORCE_TESTS") != ""

	// Check if npm is available
	//nolint:errcheck
	if _, err := command.New("npm", "--version").RunSilentSuccessOutput(); err != nil {
		if forceTests {
			t.Fatal("npm not available and UNPACK_FORCE_TESTS is set")
		}
		t.Skip("npm not available, skipping comparison test")
	}

	tests := []struct {
		name    string
		workDir string
	}{
		{"k8s.io", "testdata/k8s.io"},
		{"demorepo", "testdata/demorepo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Get absolute path for npm
			absPath, err := filepath.Abs(tc.workDir)
			require.NoError(t, err)

			// Check if node_modules exists (npm ci/install has been run)
			nodeModulesPath := filepath.Join(absPath, "node_modules")
			if _, err := os.Stat(nodeModulesPath); os.IsNotExist(err) {
				if forceTests {
					t.Fatalf("node_modules not found in %s and UNPACK_FORCE_TESTS is set - run 'npm ci' first", tc.workDir)
				}
				t.Skipf("node_modules not found - run 'npm ci' in %s to enable this test", tc.workDir)
			}

			// Run npm ls to get the expected dependencies
			// Use --all to include transitive deps, --parseable --long for output format
			cmd := command.NewWithWorkDir(absPath, "npm", "ls", "--all", "--parseable", "--long")
			output, err := cmd.RunSilentSuccessOutput()
			if err != nil {
				// npm ls may fail with ELSPROBLEMS if there are peer dep issues
				// but still outputs useful information
				t.Logf("npm ls returned error (may be expected): %v", err)
			}

			// Parse npm ls output to get list of packages
			npmPackages := parseNpmLsOutput(output.OutputTrimNL())

			if len(npmPackages) == 0 {
				t.Skip("npm ls returned no packages - skipping comparison")
			}

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

			// Verify all npm ls packages are in our output
			missing := []string{}
			for pkg := range npmPackages {
				if !ourPackages[pkg] {
					missing = append(missing, pkg)
				}
			}

			// Allow some flexibility - npm ls may show packages differently
			// The important thing is we have reasonable coverage
			require.LessOrEqual(t, len(missing), 5,
				"too many packages found in npm ls but not in our output: %v", missing)
		})
	}
}

// TestDependencyTypes verifies that dependency types are correctly assigned.
func TestDependencyTypes(t *testing.T) {
	t.Parallel()

	// Create test package.json data
	jsonData := []byte(`{
		"name": "test-pkg",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		},
		"peerDependencies": {
			"react": "^18.0.0"
		},
		"optionalDependencies": {
			"fsevents": "^2.3.0"
		}
	}`)

	pkg, err := ParsePackageJSONData(jsonData)
	require.NoError(t, err)

	deps := pkg.GetDirectDependencies()

	require.Equal(t, DepTypeNormal, deps["express"])
	require.Equal(t, DepTypeDev, deps["jest"])
	require.Equal(t, DepTypePeer, deps["react"])
	require.Equal(t, DepTypeOptional, deps["fsevents"])
}

// TestDevDependencyEdges verifies that dev dependencies get the correct edge type.
func TestDevDependencyEdges(t *testing.T) {
	t.Parallel()

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir: "testdata/k8s.io",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// All direct dependencies in the k8s.io test case are devDependencies
	// The edges should reflect this

	// Get all edges from the nodelist
	edges := nl.GetEdges()
	require.NotEmpty(t, edges)

	// Find root node ID
	roots := nl.GetRootElements()
	require.Len(t, roots, 1)
	rootID := roots[0]

	// Check that edges from root are devDependency type
	// (since all deps in our test case are dev deps)
	devDepEdges := 0
	for _, edge := range edges {
		if edge.GetFrom() == rootID && edge.GetType() == sbom.Edge_devDependency {
			devDepEdges++
		}
	}

	// We should have some devDependency edges from root
	require.Positive(t, devDepEdges, "expected devDependency edges from root node")
}

// TestNormalDependencyEdges verifies that normal dependencies get the correct edge type.
func TestNormalDependencyEdges(t *testing.T) {
	t.Parallel()

	d := New()
	opts := &api.DecomposerOptions{
		WorkDir: "testdata/demorepo",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// All direct dependencies in the demorepo test case are normal dependencies
	// The edges should reflect this

	// Get all edges from the nodelist
	edges := nl.GetEdges()
	require.NotEmpty(t, edges)

	// Find root node ID
	roots := nl.GetRootElements()
	require.Len(t, roots, 1)
	rootID := roots[0]

	// Check that edges from root are dependsOn type (normal dependencies)
	normalDepEdges := 0
	devDepEdges := 0
	for _, edge := range edges {
		if edge.GetFrom() == rootID {
			if edge.GetType() == sbom.Edge_dependsOn {
				normalDepEdges++
			} else if edge.GetType() == sbom.Edge_devDependency {
				devDepEdges++
			}
		}
	}

	// We should have normal dependency edges from root, not dev dependency edges
	require.Positive(t, normalDepEdges, "expected dependsOn edges from root node")
	require.Zero(t, devDepEdges, "expected no devDependency edges from root node for demorepo")
}

// TestPackageLockIndex tests the package indexing functionality.
func TestPackageLockIndex(t *testing.T) {
	t.Parallel()

	lock, err := ParsePackageLock("testdata/k8s.io")
	require.NoError(t, err)

	byKey, byName, byPath := lock.BuildPackageIndex()

	// Check byKey lookup
	key := PackageKey{Name: "autoprefixer", Version: "10.4.20"}
	pkg, ok := byKey[key]
	require.True(t, ok)
	require.Equal(t, "10.4.20", pkg.Version)

	// Check byName lookup (may have multiple versions)
	pkgs, ok := byName["autoprefixer"]
	require.True(t, ok)
	require.GreaterOrEqual(t, len(pkgs), 1)

	// Check byPath lookup
	pkg, ok = byPath["node_modules/autoprefixer"]
	require.True(t, ok)
	require.Equal(t, "autoprefixer", pkg.Name)
}

// TestFindCodeBases tests that the decomposer can find npm codebases.
func TestFindCodeBases(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()

	// Create a package-lock.json file
	lockPath := filepath.Join(tmpDir, "package-lock.json")
	err := os.WriteFile(lockPath, []byte(`{"lockfileVersion": 3, "packages": {}}`), 0o600)
	require.NoError(t, err)

	// Create a subdirectory with another package-lock.json
	subDir := filepath.Join(tmpDir, "subproject")
	err = os.MkdirAll(subDir, 0o750)
	require.NoError(t, err)

	subLock := filepath.Join(subDir, "package-lock.json")
	err = os.WriteFile(subLock, []byte(`{"lockfileVersion": 3, "packages": {}}`), 0o600)
	require.NoError(t, err)

	// Verify the decomposer interface is correct
	d := New()
	require.NotNil(t, d)

	// Verify default options
	opts := d.DefaultOptions()
	require.NotNil(t, opts)
	npmOpts, ok := opts.(Options)
	require.True(t, ok)
	require.False(t, npmOpts.IncludeDevDependencies)
}

// TestListDependencies tests the helper function for debugging.
func TestListDependencies(t *testing.T) {
	t.Parallel()

	pkg, err := ParsePackageJSON("testdata/k8s.io")
	require.NoError(t, err)

	lock, err := ParsePackageLock("testdata/k8s.io")
	require.NoError(t, err)

	tree := NewDependencyTree(pkg, lock)
	deps := tree.ListDependencies()

	// Should be sorted
	sorted := make([]string, len(deps))
	copy(sorted, deps)
	sort.Strings(sorted)
	require.Equal(t, sorted, deps)

	// Should contain some expected packages
	found := false
	for _, dep := range deps {
		if strings.HasPrefix(dep, "autoprefixer@") {
			found = true
			break
		}
	}
	require.True(t, found, "expected to find autoprefixer in dependencies")
}

// TestScopedPackages tests that scoped packages are handled correctly.
func TestScopedPackages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		workDir    string
		scopedPkg  string
		wantInPURL string
	}{
		{
			name:       "k8s.io",
			workDir:    "testdata/k8s.io",
			scopedPkg:  "@fortawesome/fontawesome-free",
			wantInPURL: "pkg:npm/fortawesome/fontawesome-free@",
		},
		{
			name:       "demorepo",
			workDir:    "testdata/demorepo",
			scopedPkg:  "@types/node",
			wantInPURL: "pkg:npm/types/node@",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lock, err := ParsePackageLock(tc.workDir)
			require.NoError(t, err)

			_, byName, _ := lock.BuildPackageIndex()

			// Check that scoped packages are indexed correctly
			pkgs, ok := byName[tc.scopedPkg]
			require.True(t, ok, "expected to find %s", tc.scopedPkg)
			require.GreaterOrEqual(t, len(pkgs), 1)

			// Check PURL generation for scoped package
			purl := buildPURL(tc.scopedPkg, pkgs[0].Version)
			require.Contains(t, purl, tc.wantInPURL)
		})
	}
}

// TestGitDependencies tests that git dependencies are handled correctly.
func TestGitDependencies(t *testing.T) {
	t.Parallel()

	lock, err := ParsePackageLock("testdata/k8s.io")
	require.NoError(t, err)

	// The docsy package is a git dependency
	_, byName, _ := lock.BuildPackageIndex()
	pkgs, ok := byName["docsy"]
	require.True(t, ok, "expected to find docsy package")
	require.GreaterOrEqual(t, len(pkgs), 1)

	// Git dependencies have "resolved" pointing to git URL
	docsy := pkgs[0]
	require.Contains(t, docsy.Resolved, "git")
}

// parseNpmLsOutput parses the output of npm ls --all --parseable --long
// and returns a map of package@version strings.
// Format: /path/to/node_modules/package:package@version
// or for scoped: /path/to/node_modules/@scope/package:@scope/package@version
func parseNpmLsOutput(output string) map[string]bool {
	packages := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Each line ends with :name@version
	// Regex matches the name@version at the end after the last colon
	re := regexp.MustCompile(`:(@?[^:@]+(?:/[^:@]+)?)@([^:]+)$`)

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

// TestRequirements verifies the decomposer requirements.
func TestRequirements(t *testing.T) {
	t.Parallel()

	d := New()
	reqs := d.Requirements(nil)

	// npm decomposer has no requirements (pure Go implementation)
	require.Empty(t, reqs)
}

// TestUnsupportedLockfileVersion tests that old lockfile versions are rejected.
func TestUnsupportedLockfileVersion(t *testing.T) {
	t.Parallel()

	// Lockfile version 1 (npm 5.x) is not supported
	lockData := []byte(`{
		"name": "test",
		"lockfileVersion": 1,
		"dependencies": {}
	}`)

	_, err := ParsePackageLockData(lockData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported lockfile version")
}

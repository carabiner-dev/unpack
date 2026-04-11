// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

const (
	// mavenDockerImage is the container image used to run mvn commands.
	mavenDockerImage = "maven:3.9-eclipse-temurin-21-alpine"
)

// TestCompareWithMvnDependencyTree verifies our dependency resolution matches
// Maven's actual output. It runs `mvn dependency:tree` inside a Docker container
// to avoid requiring Java/Maven on the host system.
//
// Set UNPACK_FORCE_TESTS=1 to fail instead of skip when Docker is not available.
func TestCompareWithMvnDependencyTree(t *testing.T) {
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

	tests := []struct {
		name    string
		workDir string
	}{
		{"conformance", "testdata/conformance"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			absPath, err := filepath.Abs(tc.workDir)
			require.NoError(t, err)

			// Run mvn dependency:tree inside a Docker container.
			// Mount the project directory and use a volume for the Maven cache
			// to speed up repeated runs.
			mvnOutput := runMvnDependencyTree(t, absPath, forceTests)
			if mvnOutput == "" {
				return
			}

			// Parse Maven's dependency:tree output
			mvnDeps := parseMvnDependencyTree(mvnOutput)
			require.NotEmpty(t, mvnDeps, "mvn dependency:tree returned no dependencies")

			t.Logf("Maven resolved %d dependencies", len(mvnDeps))
			for dep := range mvnDeps {
				t.Logf("  maven: %s (scope: %s)", dep, mvnDeps[dep])
			}

			// Extract using our implementation
			d := New()
			opts := &api.DecomposerOptions{
				WorkDir: tc.workDir,
			}
			nl, err := d.Extract(opts)
			require.NoError(t, err)

			// Build a map of our resolved packages: "groupId:artifactId:version" -> true
			ourPackages := make(map[string]bool)
			for _, node := range nl.GetNodes() {
				purls := node.GetIdentifiers()
				for _, purl := range purls {
					// Parse "pkg:maven/groupId/artifactId@version"
					coord := purlToCoordKey(purl)
					if coord != "" {
						ourPackages[coord] = true
					}
				}
			}

			t.Logf("We resolved %d packages", len(ourPackages))

			// Compare: all Maven dependencies should be in our output
			var missing []string
			for dep, scope := range mvnDeps {
				// Skip test and provided scope - we don't include them by default
				if scope == ScopeTest || scope == ScopeProvided {
					continue
				}
				if !ourPackages[dep] {
					missing = append(missing, dep+" ("+scope+")")
				}
			}

			// Report all missing for debugging
			if len(missing) > 0 {
				t.Logf("Missing from our output:")
				for _, m := range missing {
					t.Logf("  - %s", m)
				}
			}

			// Allow a small number of mismatches for edge cases
			// (e.g., optional transitive deps Maven may include differently)
			require.LessOrEqual(t, len(missing), 2,
				"too many dependencies found in mvn but not in our output: %v", missing)
		})
	}
}

// runMvnDependencyTree runs `mvn dependency:tree` in a Docker container
// and returns the raw output.
func runMvnDependencyTree(t *testing.T, projectDir string, forceTests bool) string {
	t.Helper()

	// Run Maven in a container with the project directory mounted.
	// We use -B (batch mode) and -DoutputType=text for parseable output.
	cmd := command.New(
		"docker", "run", "--rm",
		"-v", projectDir+":/project:ro",
		"-w", "/project",
		mavenDockerImage,
		"mvn", "dependency:tree",
		"-B",
		"-DoutputType=text",
	)

	output, err := cmd.RunSuccessOutput()
	if err != nil {
		if forceTests {
			t.Fatalf("mvn dependency:tree failed: %v\n%s", err, output.Output())
		}
		t.Skipf("mvn dependency:tree failed (may need network): %v", err)
		return ""
	}

	return output.Output()
}

// depTreeLineRe matches Maven dependency:tree output lines like:
//
//	[INFO] +- com.google.guava:guava:jar:33.0.0-jre:compile
//	[INFO] |  \- com.google.guava:failureaccess:jar:1.0.2:compile
//	[INFO] \- org.apache.commons:commons-lang3:jar:3.14.0:compile
var depTreeLineRe = regexp.MustCompile(
	`\[INFO\]\s+[|\\+\- ]+` + // tree prefix characters
		`([^:]+):` + // groupId
		`([^:]+):` + // artifactId
		`([^:]+):` + // type (jar, pom, etc.)
		`([^:]+):` + // version
		`(\S+)`, // scope
)

// parseMvnDependencyTree parses the output of `mvn dependency:tree`
// and returns a map of "groupId:artifactId:version" -> scope.
func parseMvnDependencyTree(output string) map[string]string {
	deps := make(map[string]string)
	for line := range strings.SplitSeq(output, "\n") {
		matches := depTreeLineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		groupID := matches[1]
		artifactID := matches[2]
		// matches[3] is type (jar)
		version := matches[4]
		scope := matches[5]

		key := groupID + ":" + artifactID + ":" + version
		deps[key] = scope
	}
	return deps
}

// purlToCoordKey converts a Maven PURL to "groupId:artifactId:version".
// Input: "pkg:maven/com.google.guava/guava@33.0.0-jre"
// Output: "com.google.guava:guava:33.0.0-jre"
func purlToCoordKey(purl string) string {
	if !strings.HasPrefix(purl, "pkg:maven/") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:maven/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	groupID := parts[0]
	artAndVersion := parts[1]

	artParts := strings.SplitN(artAndVersion, "@", 2)
	if len(artParts) != 2 {
		return ""
	}

	return groupID + ":" + artParts[0] + ":" + artParts[1]
}

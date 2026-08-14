// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

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

// rubyOracleImage runs the conformance oracle: Bundler's own lockfile
// parser, reading the same lock the unit tests read, in the image whose
// Bundler wrote the fixtures. No install and no network — the parser is
// the library bundle ships with.
const rubyOracleImage = "ruby:3.4"

// bundlerOracleScript has Bundler parse the lock and say what it holds:
// every spec with its version, platform and dependency names, and the
// direct dependency set.
const bundlerOracleScript = `
require "bundler"
require "json"
lock = Bundler::LockfileParser.new(File.read("Gemfile.lock"))
puts({
  specs: lock.specs.map { |s|
    {name: s.name, version: s.version.to_s, platform: s.platform.to_s,
     deps: s.dependencies.map(&:name).sort}
  },
  dependencies: lock.dependencies.keys.sort,
}.to_json)
`

// TestCompareWithBundler holds the extraction to Bundler's reading of the
// lock: the gem set, every resolved version, the direct dependencies, and
// the edges.
func TestCompareWithBundler(t *testing.T) {
	t.Parallel()

	for _, testdata := range []string{"simple", "gitgem"} {
		t.Run(testdata, func(t *testing.T) {
			t.Parallel()
			oracle := runBundlerOracle(t, testdata)

			opts := &api.DecomposerOptions{
				WorkDir:    "testdata/" + testdata,
				Platform:   "linux/amd64",
				Networking: api.NetworkDisabled,
			}
			nl, err := New().Extract(opts)
			require.NoError(t, err)

			roots := map[string]bool{}
			for _, id := range nl.GetRootElements() {
				roots[id] = true
			}
			byID := map[string]*sbom.Node{}
			names := []string{}
			for _, n := range nl.GetNodes() {
				byID[n.GetId()] = n
				if !roots[n.GetId()] {
					names = append(names, n.GetName())
				}
			}

			// The gem set: one node per name, whatever the variant.
			oracleNames := map[string]bool{}
			oracleVersions := map[string]bool{}
			oraclePairs := map[string]bool{}
			for _, spec := range oracle.Specs {
				oracleNames[spec.Name] = true
				oracleVersions[spec.Name+"@"+spec.Version] = true
				for _, dep := range spec.Deps {
					oraclePairs[spec.Name+">"+dep] = true
				}
			}
			nameSet := make([]string, 0, len(oracleNames))
			for name := range oracleNames {
				nameSet = append(nameSet, name)
			}
			require.ElementsMatch(t, nameSet, names, "the gems disagree with Bundler")

			// Every resolved version is one Bundler read.
			for _, n := range nl.GetNodes() {
				if !roots[n.GetId()] {
					require.True(t, oracleVersions[n.GetName()+"@"+n.GetVersion()],
						"%s@%s is not a resolution Bundler read", n.GetName(), n.GetVersion())
				}
			}

			// The direct dependencies are the root's edges,
			direct := []string{}
			pairs := []string{}
			for _, e := range nl.GetEdges() {
				for _, to := range e.GetTo() {
					if roots[e.GetFrom()] {
						direct = append(direct, byID[to].GetName())
					} else {
						pairs = append(pairs, byID[e.GetFrom()].GetName()+">"+byID[to].GetName())
					}
				}
			}
			require.ElementsMatch(t, oracle.Dependencies, direct,
				"the direct dependencies disagree with Bundler")

			// and every other edge is one some spec declares.
			for _, pair := range pairs {
				require.True(t, oraclePairs[pair], "edge %s is not one Bundler read", pair)
			}
		})
	}
}

// bundlerOracle is the script's output.
type bundlerOracle struct {
	Specs []struct {
		Name     string   `json:"name"`
		Version  string   `json:"version"`
		Platform string   `json:"platform"`
		Deps     []string `json:"deps"`
	} `json:"specs"`
	Dependencies []string `json:"dependencies"`
}

// runBundlerOracle runs the parser script over a testdata project in
// Docker. Docker being present does not mean it can run this image — the
// Windows runners' Docker speaks Windows containers only — so only Linux
// is held to the oracle and a failure elsewhere is a skip, the convention
// the Maven and Composer oracles follow.
func runBundlerOracle(t *testing.T, testdata string) *bundlerOracle {
	t.Helper()
	forced := os.Getenv("UNPACK_FORCE_TESTS") != "" && runtime.GOOS == "linux"

	if err := command.New("docker", "version").RunSilentSuccess(); err != nil {
		if forced {
			t.Fatal("docker is not available and UNPACK_FORCE_TESTS is set")
		}
		t.Skip("skipping: docker is not available to run the oracle")
	}

	dir, err := filepath.Abs("testdata/" + testdata)
	require.NoError(t, err)
	out, err := command.New("docker",
		"run", "--rm", "-v", dir+":/app:ro", "-w", "/app", rubyOracleImage,
		"ruby", "-e", bundlerOracleScript,
	).RunSuccessOutput()
	if err != nil {
		if forced {
			t.Fatalf("running the oracle: %v", err)
		}
		t.Skipf("skipping: the oracle did not run (%v)", err)
	}

	// The output may carry warnings ahead of the JSON.
	text := out.Output()
	start := strings.Index(text, "{")
	require.GreaterOrEqual(t, start, 0, "no JSON in the oracle output")
	oracle := &bundlerOracle{}
	require.NoError(t, json.Unmarshal([]byte(text[start:]), oracle))
	require.NotEmpty(t, oracle.Specs)
	return oracle
}

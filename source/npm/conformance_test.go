// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// The conformance tests hold each lock reader to the tool that wrote the
// lock: pnpm ls, yarn list and yarn info all answer from the lockfile
// alone, no install needed, so the same fixtures the unit tests read are
// read back by their own tools. Runs need npx (node); without it the tests
// skip, and under UNPACK_FORCE_TESTS they fail instead, since CI installs
// node everywhere.

// The tool versions the oracles run, pinned: an oracle that drifts under
// the tests is not an oracle.
//
// The version 6 pnpm lock has no oracle case: answering ls from the lock
// alone is a pnpm 9 ability, pnpm 11 answers an empty tree for a lock it
// no longer speaks, and pnpm 8 answers empty without an install. The v6
// fixture is the same project as the v9 one, whose truth is compared
// here, and the v6-specific spelling is pinned by the unit tests against
// real pnpm 8 output.
const (
	pnpmOracleVersion = "pnpm@11.21.0"
	yarnOracleVersion = "yarn@1.22.22"
	berryOracleName   = "yarn@4.12.0"
)

// runOracle runs a tool through npx in a testdata directory.
func runOracle(t *testing.T, testdata string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("npx"); err != nil {
		if os.Getenv("UNPACK_FORCE_TESTS") != "" {
			t.Fatal("npx is not available and UNPACK_FORCE_TESTS is set")
		}
		t.Skip("skipping: npx is not available to run the oracle")
	}

	out, err := command.NewWithWorkDir(
		"testdata/"+testdata, "npx", append([]string{"--yes"}, args...)...,
	).RunSuccessOutput()
	if err != nil {
		if os.Getenv("UNPACK_FORCE_TESTS") != "" {
			t.Fatalf("running the oracle: %v", err)
		}
		t.Skipf("skipping: the oracle did not run (%v)", err)
	}
	return out.Output()
}

// extractedSet runs the decomposer and returns its non-root packages as
// name@version strings, the shape every oracle is reduced to.
func extractedSet(t *testing.T, testdata string, opts *api.DecomposerOptions) []string {
	t.Helper()
	set, _ := extractedGraph(t, testdata, opts)
	return set
}

// extractedGraph returns the non-root package set and the package-to-
// package edges as "from>to" pairs. Root edges are left out: the roots'
// versions come from manifests, which the oracles state differently.
func extractedGraph(t *testing.T, testdata string, opts *api.DecomposerOptions) (set, pairs []string) {
	t.Helper()
	nl := extractPnpmTree(t, testdata, opts)

	roots := map[string]bool{}
	for _, id := range nl.GetRootElements() {
		roots[id] = true
	}
	names := map[string]string{}
	for _, n := range nl.GetNodes() {
		names[n.GetId()] = n.GetName() + "@" + n.GetVersion()
		if !roots[n.GetId()] {
			set = append(set, n.GetName()+"@"+n.GetVersion())
		}
	}

	seen := map[string]bool{}
	for _, e := range nl.GetEdges() {
		if roots[e.GetFrom()] {
			continue
		}
		for _, to := range e.GetTo() {
			if roots[to] {
				continue
			}
			pair := names[e.GetFrom()] + ">" + names[to]
			if !seen[pair] {
				seen[pair] = true
				pairs = append(pairs, pair)
			}
		}
	}
	return set, pairs
}

// TestCompareWithPnpmLs holds the pnpm reader to pnpm ls --json, in the
// dependency configurations both sides can name.
func TestCompareWithPnpmLs(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		testdata string
		oracle   string
		lsArgs   []string
		opts     *api.DecomposerOptions
	}{
		"production only": {
			testdata: "pnpm",
			oracle:   pnpmOracleVersion,
			lsArgs:   []string{"ls", "--prod", "--no-optional", "--depth", "Infinity", "--json"},
			opts:     &api.DecomposerOptions{},
		},
		"everything": {
			testdata: "pnpm",
			oracle:   pnpmOracleVersion,
			lsArgs:   []string{"ls", "--depth", "Infinity", "--json"},
			opts:     &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true},
		},
		"a workspace": {
			testdata: "pnpmws",
			oracle:   pnpmOracleVersion,
			lsArgs:   []string{"-r", "ls", "--depth", "Infinity", "--json"},
			opts:     &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := runOracle(t, tc.testdata, append([]string{tc.oracle}, tc.lsArgs...)...)
			oracleSet, oraclePairs := parsePnpmLs(t, out)
			set, pairs := extractedGraph(t, tc.testdata, tc.opts)
			require.ElementsMatch(t, oracleSet, set, "the packages disagree with pnpm ls")
			require.ElementsMatch(t, oraclePairs, pairs, "the edges disagree with pnpm ls")
		})
	}
}

// pnpmLsDep is one entry of pnpm ls --json, recursively.
type pnpmLsDep struct {
	Version      string               `json:"version"`
	Dependencies map[string]pnpmLsDep `json:"dependencies"`
}

type pnpmLsProject struct {
	Dependencies         map[string]pnpmLsDep `json:"dependencies"`
	DevDependencies      map[string]pnpmLsDep `json:"devDependencies"`
	OptionalDependencies map[string]pnpmLsDep `json:"optionalDependencies"`
}

func parsePnpmLs(t *testing.T, out string) (set, pairs []string) {
	t.Helper()
	projects := []pnpmLsProject{}
	require.NoError(t, json.Unmarshal([]byte(out), &projects))

	seen := map[string]bool{}
	seenPairs := map[string]bool{}
	var collect func(parent string, deps map[string]pnpmLsDep)
	collect = func(parent string, deps map[string]pnpmLsDep) {
		for name, dep := range deps {
			// A link: is another project of the workspace, listed as a
			// root of its own.
			if strings.HasPrefix(dep.Version, "link:") {
				continue
			}
			key := name + "@" + dep.Version
			seen[key] = true
			// The nesting states the edges; the ones under a project are
			// root edges, which the comparison leaves out.
			if parent != "" {
				seenPairs[parent+">"+key] = true
			}
			collect(key, dep.Dependencies)
		}
	}
	for _, project := range projects {
		collect("", project.Dependencies)
		collect("", project.DevDependencies)
		collect("", project.OptionalDependencies)
	}

	for key := range seen {
		set = append(set, key)
	}
	for pair := range seenPairs {
		pairs = append(pairs, pair)
	}
	return set, pairs
}

// TestCompareWithYarnList holds the classic yarn reader to yarn list,
// which answers from the lockfile.
func TestCompareWithYarnList(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		listArgs []string
		opts     *api.DecomposerOptions
	}{
		// yarn list --prod keeps the optional dependencies: installs do.
		"production": {
			listArgs: []string{"list", "--prod", "--json", "--no-progress"},
			opts:     &api.DecomposerOptions{IncludeOptional: true},
		},
		"everything": {
			listArgs: []string{"list", "--json", "--no-progress"},
			opts:     &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := runOracle(t, "yarn", append([]string{yarnOracleVersion}, tc.listArgs...)...)
			require.ElementsMatch(t, parseYarnList(t, out), extractedSet(t, "yarn", tc.opts),
				"the packages disagree with yarn list")
		})
	}
}

func parseYarnList(t *testing.T, out string) []string {
	t.Helper()
	type yarnTree struct {
		Name   string `json:"name"`
		Shadow bool   `json:"shadow"`
	}
	var parsed struct {
		Data struct {
			Trees []yarnTree `json:"trees"`
		} `json:"data"`
	}

	// yarn emits NDJSON; the tree is the line that carries one.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"type":"tree"`) {
			require.NoError(t, json.Unmarshal([]byte(line), &parsed))
			break
		}
	}
	require.NotEmpty(t, parsed.Data.Trees)

	set := []string{}
	for _, tree := range parsed.Data.Trees {
		// Top-level entries are the resolved packages; shadowed children
		// restate ranges.
		if !tree.Shadow {
			set = append(set, tree.Name)
		}
	}
	return set
}

// TestCompareWithYarnBerryInfo holds the berry reader to yarn info, which
// answers from the lock and the project alone. The oracle's output names
// virtual packages — the peer-dependency clones — and the comparison
// proves they collapse onto one node each.
func TestCompareWithYarnBerryInfo(t *testing.T) {
	t.Parallel()

	for name, testdata := range map[string]string{
		"a single project": "yarnberry",
		"a workspace":      "yarnberryws",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// yarn drops install state into .yarn even for a read-only
			// query; the fixture stays a fixture.
			t.Cleanup(func() { os.RemoveAll("testdata/" + testdata + "/.yarn") })
			out := runOracle(t, testdata,
				"corepack@latest", berryOracleName, "info", "--all", "--json")
			opts := &api.DecomposerOptions{IncludeDev: true, IncludeOptional: true}
			oracleSet, oraclePairs := parseBerryInfo(t, out)
			set, pairs := extractedGraph(t, testdata, opts)
			require.ElementsMatch(t, oracleSet, set, "the packages disagree with yarn info")
			require.ElementsMatch(t, oraclePairs, pairs, "the edges disagree with yarn info")
		})
	}
}

func parseBerryInfo(t *testing.T, out string) (set, pairs []string) {
	t.Helper()
	seen := map[string]bool{}
	seenPairs := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Value    string `json:"value"`
			Children struct {
				Version      string `json:"version"`
				Dependencies []struct {
					Locator string `json:"locator"`
				} `json:"dependencies"`
			} `json:"children"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &entry))

		// Workspaces are the roots, listed apart by their protocol.
		if strings.Contains(entry.Value, "@workspace:") {
			continue
		}
		// A virtual locator is a peer-dependency clone of a real package:
		// name@virtual:<hash>#npm:version names the same content. The
		// oracle states them, and the comparison holding anyway is what
		// proves the reader collapses them onto one node each.
		name, err := yarnSelectorName(stripVirtual(entry.Value))
		require.NoError(t, err)
		key := name + "@" + entry.Children.Version
		seen[key] = true

		for _, dep := range entry.Children.Dependencies {
			if strings.Contains(dep.Locator, "@workspace:") {
				continue
			}
			child := strings.Replace(stripVirtual(dep.Locator), "@npm:", "@", 1)
			seenPairs[key+">"+child] = true
		}
	}

	for key := range seen {
		set = append(set, key)
	}
	for pair := range seenPairs {
		pairs = append(pairs, pair)
	}
	require.NotEmpty(t, set)
	return set, pairs
}

// stripVirtual reduces a virtual locator to the real one it clones.
func stripVirtual(locator string) string {
	name, rest, found := strings.Cut(locator, "@virtual:")
	if !found {
		return locator
	}
	if _, ref, hasRef := strings.Cut(rest, "#"); hasRef {
		return name + "@" + ref
	}
	return locator
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// uvDockerImage runs the conformance oracle when uv is not on the PATH. The
// distroless image carries the binary at /uv.
const uvDockerImage = "ghcr.io/astral-sh/uv:latest"

// TestCompareWithUvExport holds the extraction to what uv itself says the
// lock resolves to. uv export --frozen --offline writes the pinned set from
// uv.lock alone, with the marker each entry is conditional on, so the same
// lock our tree builder reads is read back by the tool that wrote it.
//
// The oracle entries' markers are evaluated with our own evaluator, which
// would be circular if the evaluator were not itself held to Python's
// packaging library by TestAgainstPythonOracle: that test vouches for the
// markers, this one for everything on top — reachability, fork selection,
// dev groups, extras, and the artifact hashes.
//
// Runs with uv from the PATH, in Docker when there is no uv, and is skipped
// when there is neither. Set UNPACK_FORCE_TESTS=1 to fail instead of skip.
func TestCompareWithUvExport(t *testing.T) {
	t.Parallel()
	requireUv(t)

	linux312 := [3]string{"linux", "amd64", "3.12"}
	linux310 := [3]string{"linux", "amd64", "3.10"}
	windows312 := [3]string{"windows", "amd64", "3.12"}

	for name, tc := range map[string]struct {
		project    string
		exportArgs []string
		configure  func(*api.DecomposerOptions)
		envs       [][3]string
	}{
		"runtime dependencies": {
			project:    "simple",
			exportArgs: []string{"--no-dev"},
			envs:       [][3]string{linux312, linux310, windows312},
		},
		"with the dev group": {
			project:    "simple",
			exportArgs: []string{}, // dev groups are in by default for uv export
			configure:  func(o *api.DecomposerOptions) { o.IncludeDev = true },
			envs:       [][3]string{linux312, linux310},
		},
		"with the extras": {
			project:    "simple",
			exportArgs: []string{"--no-dev", "--all-extras"},
			configure:  func(o *api.DecomposerOptions) { o.IncludeOptional = true },
			envs:       [][3]string{linux312},
		},
		"a forked resolution": {
			project:    "forked",
			exportArgs: []string{"--no-dev"},
			envs: [][3]string{
				linux312, linux310, {"linux", "amd64", "3.11"}, {"darwin", "arm64", "3.12"},
			},
		},
		"a workspace": {
			project:    "workspace",
			exportArgs: []string{"--no-dev"},
			envs:       [][3]string{linux312, windows312},
		},
		"a git dependency": {
			project:    "gitdep",
			exportArgs: []string{"--no-dev"},
			envs:       [][3]string{linux312},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			oracle := parseExport(t, uvExport(t, tc.project, tc.exportArgs...))

			for _, env := range tc.envs {
				opts := &api.DecomposerOptions{Networking: api.NetworkDisabled}
				opts.SetDriverOptions(New(), &Options{
					Platform:      env[0] + "/" + env[1],
					PythonVersion: env[2],
				})
				if tc.configure != nil {
					tc.configure(opts)
				}
				nl := extract(t, tc.project, opts)
				compareWithOracle(t, nl, oracle, env)
			}
		})
	}
}

// oracleEntry is one package of a uv export.
type oracleEntry struct {
	name    string
	version string // empty for git dependencies: the export names a commit
	marker  string
	hashes  map[string]bool
}

// parseExport reads the requirements format uv export writes: one package
// per logical line as name==version with an optional " ; marker", its hash
// list in --hash continuations, project and workspace members as -e lines.
func parseExport(t *testing.T, out string) []oracleEntry {
	t.Helper()
	entries := []oracleEntry{}

	for _, line := range strings.Split(strings.ReplaceAll(out, " \\\n", " "), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-e ") {
			continue
		}

		fields := strings.Fields(line)
		entry := oracleEntry{hashes: map[string]bool{}}

		requirement, marker, _ := strings.Cut(line, " ; ")
		if i := strings.Index(marker, " --hash="); i >= 0 {
			marker = marker[:i]
		}
		entry.marker = strings.TrimSpace(marker)

		switch {
		case strings.Contains(fields[0], "=="):
			name, version, _ := strings.Cut(fields[0], "==")
			entry.name, entry.version = NormalizeName(name), version
		case len(fields) >= 3 && fields[1] == "@":
			// A git dependency: name @ git+url@commit, no version.
			entry.name = NormalizeName(fields[0])
			entry.marker = "" // a direct URL requirement carries none here
		default:
			t.Fatalf("unparseable export line: %q", line)
		}

		for _, field := range strings.Fields(requirement) {
			if hash, ok := strings.CutPrefix(field, "--hash=sha256:"); ok {
				entry.hashes[hash] = true
			}
		}
		entries = append(entries, entry)
	}

	require.NotEmpty(t, entries)
	return entries
}

// compareWithOracle requires the extracted graph to hold exactly the
// packages whose oracle markers hold in the environment, and every hash we
// selected to be one uv knows for its package. The export lists every
// artifact's hash, so membership proves the hash is real rather than that
// the right artifact was chosen: which wheel the selection picks is pinned
// by the unit tests.
func compareWithOracle(t *testing.T, nl *sbom.NodeList, oracle []oracleEntry, env [3]string) {
	t.Helper()

	environment, err := NewEnvironment(env[0], env[1], env[2])
	require.NoError(t, err)

	// What uv says the environment installs.
	expected := []string{}
	oracleHashes := map[string]map[string]bool{}
	versioned := map[string]bool{}
	for _, entry := range oracle {
		holds, err := environment.Evaluate(entry.marker)
		require.NoError(t, err, "the oracle's marker %q", entry.marker)
		if !holds {
			continue
		}
		if entry.version == "" {
			expected = append(expected, entry.name)
			continue
		}
		expected = append(expected, entry.name+"=="+entry.version)
		versioned[entry.name] = true
		oracleHashes[entry.name] = entry.hashes
	}

	// What we extracted, the project's own packages aside: uv export does
	// not emit those.
	roots := map[string]bool{}
	for _, id := range nl.GetRootElements() {
		roots[id] = true
	}
	extracted := []string{}
	for _, node := range nl.GetNodes() {
		if roots[node.GetId()] {
			continue
		}
		if versioned[node.GetName()] {
			extracted = append(extracted, node.GetName()+"=="+node.GetVersion())
		} else {
			extracted = append(extracted, node.GetName())
		}

		// The artifact we hashed with has to be one uv knows.
		ours := node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)]
		if known := oracleHashes[node.GetName()]; ours != "" && len(known) > 0 {
			require.True(t, known[ours],
				"%s: our hash %s is not one uv exports", node.GetName(), ours)
		}
	}

	require.ElementsMatch(t, expected, extracted,
		"the packages for %s/%s python %s disagree with uv export", env[0], env[1], env[2])
}

// uvExport runs uv export over a testdata project, from the PATH or in
// Docker, and returns its output. Offline and frozen: the oracle reads the
// same lock the extraction reads, nothing else.
func uvExport(t *testing.T, project string, args ...string) string {
	t.Helper()

	exportArgs := append([]string{
		"export", "--frozen", "--offline", "--no-header", "--no-annotate", "--no-emit-project",
	}, args...)

	if _, err := exec.LookPath("uv"); err == nil {
		out, err := command.NewWithWorkDir(
			"testdata/"+project, "uv", exportArgs...,
		).RunSuccessOutput()
		require.NoError(t, err)
		return out.Output()
	}

	dir, err := filepath.Abs("testdata/" + project)
	require.NoError(t, err)
	out, err := command.New(
		"docker", append([]string{
			"run", "--rm", "-v", dir + ":/work:ro", "-w", "/work",
			"--entrypoint", "/uv", uvDockerImage,
		}, exportArgs...)...,
	).RunSuccessOutput()
	require.NoError(t, err)
	return out.Output()
}

// requireUv skips the test when neither uv nor Docker is available to run
// the oracle with. UNPACK_FORCE_TESTS turns the skip into a failure: CI
// installs uv on every OS, so a skip there means the setup broke, not that
// the oracle cannot run.
func requireUv(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("uv"); err == nil {
		return
	}
	if err := command.New("docker", "version").RunSilentSuccess(); err == nil {
		return
	}
	if os.Getenv("UNPACK_FORCE_TESTS") != "" {
		t.Fatal("neither uv nor docker is available and UNPACK_FORCE_TESTS is set")
	}
	t.Skip("skipping: neither uv nor docker is available to run the oracle")
}

// TestCompareWithPoetryExport holds the Poetry graph to what Poetry itself
// says the lock resolves to, through poetry export, which writes the same
// requirements format the uv oracle does. Both Poetry generations are
// compared: the export plugin reads 2.0 and 2.1 locks alike.
func TestCompareWithPoetryExport(t *testing.T) {
	t.Parallel()

	linux312 := [3]string{"linux", "amd64", "3.12"}
	linux310 := [3]string{"linux", "amd64", "3.10"}
	windows312 := [3]string{"windows", "amd64", "3.12"}

	for name, tc := range map[string]struct {
		project    string
		exportArgs []string
		configure  func(*api.DecomposerOptions)
		envs       [][3]string
	}{
		"runtime dependencies": {
			project: "poetry",
			envs:    [][3]string{linux312, linux310, windows312},
		},
		"with the dev group": {
			project:    "poetry",
			exportArgs: []string{"--with", "dev"},
			configure:  func(o *api.DecomposerOptions) { o.IncludeDev = true },
			envs:       [][3]string{linux312, linux310},
		},
		// Windows only, deliberately. poetry export rewrites the lock's
		// markers and loses the extra == arm: for the color extra it emits
		// colorama gated on Windows alone, while poetry install (and pip,
		// and uv's export of the same manifest shape) installs it on linux
		// too once the extra is enabled. Our graph follows what installs;
		// the comparison runs where exporter and installer agree.
		"with the extras": {
			project:    "poetry",
			exportArgs: []string{"--all-extras"},
			configure:  func(o *api.DecomposerOptions) { o.IncludeOptional = true },
			envs:       [][3]string{windows312},
		},
		"a legacy lock": {
			project: "poetrylegacy",
			envs:    [][3]string{linux312, windows312},
		},
		"a legacy lock with its dev group": {
			project:    "poetrylegacy",
			exportArgs: []string{"--with", "dev"},
			configure:  func(o *api.DecomposerOptions) { o.IncludeDev = true },
			envs:       [][3]string{linux312},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			oracle := parseExport(t, poetryExport(t, tc.project, tc.exportArgs...))

			for _, env := range tc.envs {
				opts := &api.DecomposerOptions{Networking: api.NetworkDisabled}
				opts.SetDriverOptions(New(), &Options{
					Platform:      env[0] + "/" + env[1],
					PythonVersion: env[2],
				})
				if tc.configure != nil {
					tc.configure(opts)
				}
				nl := extract(t, tc.project, opts)
				compareWithOracle(t, nl, oracle, env)
			}
		})
	}
}

// poetryExport runs poetry export over a testdata project through uvx,
// which fetches Poetry and its export plugin on first use. Without uvx it
// runs the one in the uv Docker image, and a failed run skips rather than
// fails — fetching Poetry needs the network — except under
// UNPACK_FORCE_TESTS, where CI is expected to have both.
func poetryExport(t *testing.T, project string, args ...string) string {
	t.Helper()

	exportArgs := append([]string{
		"--from", "poetry", "--with", "poetry-plugin-export",
		"poetry", "export", "--without-hashes",
	}, args...)

	var out string
	var err error
	if _, lookErr := exec.LookPath("uvx"); lookErr == nil {
		var result *command.Stream
		result, err = command.NewWithWorkDir("testdata/"+project, "uvx", exportArgs...).RunSuccessOutput()
		if err == nil {
			out = result.Output()
		}
	} else {
		dir, absErr := filepath.Abs("testdata/" + project)
		require.NoError(t, absErr)
		var result *command.Stream
		result, err = command.New("docker", append([]string{
			"run", "--rm", "-v", dir + ":/work:ro", "-w", "/work",
			"--entrypoint", "/uvx", uvDockerImage,
		}, exportArgs...)...).RunSuccessOutput()
		if err == nil {
			out = result.Output()
		}
	}

	if err != nil {
		if os.Getenv("UNPACK_FORCE_TESTS") != "" {
			t.Fatalf("running poetry export: %v", err)
		}
		t.Skipf("skipping: poetry export unavailable (%v)", err)
	}
	return out
}

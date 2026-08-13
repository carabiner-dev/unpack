// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

// extract runs the decomposer over one of the checked-in codebases.
func extract(t *testing.T, testdata string, opts *api.DecomposerOptions) *sbom.NodeList {
	t.Helper()
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}
	opts.WorkDir = "testdata/" + testdata
	// The graph tests are about the lock, not the index: no network. The
	// zero networking value is NetworkEssential, which would quietly turn
	// every test into a PyPI client.
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	return nl
}

// nodeNamed finds the node of a package, requiring exactly one.
func nodeNamed(t *testing.T, nl *sbom.NodeList, name string) *sbom.Node {
	t.Helper()
	var found *sbom.Node
	for _, n := range nl.GetNodes() {
		if n.GetName() == name {
			require.Nil(t, found, "more than one node named %s", name)
			found = n
		}
	}
	require.NotNil(t, found, "no node named %s", name)
	return found
}

// hasEdge says whether an edge of the type runs between the two nodes.
func hasEdge(nl *sbom.NodeList, edgeType sbom.Edge_Type, from, to *sbom.Node) bool {
	for _, e := range nl.GetEdges() {
		if e.GetType() == edgeType && e.GetFrom() == from.GetId() {
			for _, id := range e.GetTo() {
				if id == to.GetId() {
					return true
				}
			}
		}
	}
	return false
}

// linuxOpts targets a fixed environment, so assertions do not depend on the
// machine the tests run on.
func linuxOpts(t *testing.T, pythonVersion string) *api.DecomposerOptions {
	t.Helper()
	opts := &api.DecomposerOptions{}
	opts.SetDriverOptions(New(), &Options{Platform: "linux/amd64", PythonVersion: pythonVersion})
	return opts
}

func TestExtractSimple(t *testing.T) {
	t.Parallel()

	nl := extract(t, "simple", linuxOpts(t, "3.12"))

	// The project's own package roots the graph.
	require.Len(t, nl.GetRootElements(), 1)
	root := nodeNamed(t, nl, "uvdemo")
	require.Equal(t, root.GetId(), nl.GetRootElements()[0])
	require.Equal(t, "0.1.0", root.GetVersion())
	require.Equal(t, "pkg:pypi/uvdemo@0.1.0", root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	// Its two runtime dependencies, and requests's own four.
	requests := nodeNamed(t, nl, "requests")
	click := nodeNamed(t, nl, "click")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, requests))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, click))
	for _, dep := range []string{"certifi", "charset-normalizer", "idna", "urllib3"} {
		require.True(t, hasEdge(nl, sbom.Edge_dependsOn, requests, nodeNamed(t, nl, dep)),
			"requests should depend on %s", dep)
	}

	// click needs colorama only on Windows, and this is not Windows: the
	// edge's marker prunes both the edge and, nothing else needing it, the
	// package.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "colorama", n.GetName(), "the win32-only dependency should not be here")
	}

	// Neither extras nor dev groups were asked for.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "pytest", n.GetName(), "dev dependencies were not asked for")
	}
}

func TestExtractWindows(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{}
	opts.SetDriverOptions(New(), &Options{Platform: "windows/amd64", PythonVersion: "3.12"})
	nl := extract(t, "simple", opts)

	// The same lock read for Windows keeps the colorama edge.
	click := nodeNamed(t, nl, "click")
	colorama := nodeNamed(t, nl, "colorama")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, click, colorama))

	// And the wheel chosen for hashing is a Windows-installable one:
	// universal here, but never a manylinux wheel.
	require.NotContains(t, colorama.GetUrlDownload(), "manylinux")
	require.NotEmpty(t, colorama.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
}

func TestExtractDevAndOptional(t *testing.T) {
	t.Parallel()

	opts := linuxOpts(t, "3.12")
	opts.IncludeDev = true
	opts.IncludeOptional = true
	nl := extract(t, "simple", opts)

	root := nodeNamed(t, nl, "uvdemo")

	// The dev group arrives as devDependency edges from the root,
	pytest := nodeNamed(t, nl, "pytest")
	require.True(t, hasEdge(nl, sbom.Edge_devDependency, root, pytest))

	// and pytest's own runtime needs came with it.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, pytest, nodeNamed(t, nl, "pluggy")))

	// The color extra arrives as an optionalDependency edge.
	colorama := nodeNamed(t, nl, "colorama")
	require.True(t, hasEdge(nl, sbom.Edge_optionalDependency, root, colorama))

	// On Python 3.12, pytest's exceptiongroup backport (needed below 3.11)
	// stays out even though the dev group came in.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "exceptiongroup", n.GetName())
	}
}

// TestExtractForked reads the lock whose resolution forked numpy three ways
// over Python versions. One environment sees exactly one numpy.
func TestExtractForked(t *testing.T) {
	t.Parallel()

	for pythonVersion, numpyVersion := range map[string]string{
		"3.10": "2.2.6",
		"3.11": "2.4.6",
		"3.12": "2.5.2",
		"3.14": "2.5.2",
	} {
		t.Run("python "+pythonVersion, func(t *testing.T) {
			t.Parallel()
			nl := extract(t, "forked", linuxOpts(t, pythonVersion))

			numpy := nodeNamed(t, nl, "numpy")
			require.Equal(t, numpyVersion, numpy.GetVersion(),
				"python %s should see numpy %s", pythonVersion, numpyVersion)
			require.Equal(t, "pkg:pypi/numpy@"+numpyVersion,
				numpy.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

			// The interpreter-specific wheel is the hash source, so it must
			// be a wheel for this Python and platform.
			require.Contains(t, numpy.GetUrlDownload(), "cp3")
			require.Contains(t, numpy.GetUrlDownload(), "x86_64")
			require.NotEmpty(t, numpy.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
		})
	}

	// The typing-extensions backport is for Python < 3.12 only.
	t.Run("marker pruning per version", func(t *testing.T) {
		t.Parallel()
		nl := extract(t, "forked", linuxOpts(t, "3.10"))
		nodeNamed(t, nl, "typing-extensions")

		nl = extract(t, "forked", linuxOpts(t, "3.12"))
		for _, n := range nl.GetNodes() {
			require.NotEqual(t, "typing-extensions", n.GetName())
		}
	})

	// The lock's supported platforms are linux and darwin; numpy itself is
	// linux-only. A darwin extraction still works and simply has no numpy.
	t.Run("darwin sees no numpy", func(t *testing.T) {
		t.Parallel()
		opts := &api.DecomposerOptions{}
		opts.SetDriverOptions(New(), &Options{Platform: "darwin/arm64", PythonVersion: "3.12"})
		nl := extract(t, "forked", opts)
		for _, n := range nl.GetNodes() {
			require.NotEqual(t, "numpy", n.GetName())
		}
	})
}

// TestExtractExtraOfADependency covers requests[socks]: naming an extra on
// an edge pulls the extra's dependencies in under the target.
func TestExtractExtraOfADependency(t *testing.T) {
	t.Parallel()

	nl := extract(t, "extras", linuxOpts(t, "3.12"))

	requests := nodeNamed(t, nl, "requests")
	pysocks := nodeNamed(t, nl, "pysocks")
	require.True(t, hasEdge(nl, sbom.Edge_optionalDependency, requests, pysocks),
		"the socks extra's dependency hangs off requests")
}

// TestExtractDefaultPythonVersion covers the version picked when the caller
// names none: the newest fork the lock mentions, or the requires-python
// floor of an unforked lock.
func TestExtractDefaultPythonVersion(t *testing.T) {
	t.Parallel()

	// The forked lock's newest bracket is >= 3.12, so numpy comes out at
	// the version that fork resolved.
	opts := &api.DecomposerOptions{}
	opts.SetDriverOptions(New(), &Options{Platform: "linux/amd64"})
	nl := extract(t, "forked", opts)
	require.Equal(t, "2.5.2", nodeNamed(t, nl, "numpy").GetVersion())

	// The simple lock never forks: its floor (3.10) governs, and the
	// below-3.11 backports are therefore in.
	opts = &api.DecomposerOptions{}
	opts.SetDriverOptions(New(), &Options{Platform: "linux/amd64"})
	opts.IncludeDev = true
	nl = extract(t, "simple", opts)
	nodeNamed(t, nl, "exceptiongroup")
}

func TestExtractVersionAndCommitOverride(t *testing.T) {
	t.Parallel()

	opts := linuxOpts(t, "3.12")
	opts.Version = "9.9.9"
	opts.CommitHash = "abc123"
	nl := extract(t, "simple", opts)

	root := nodeNamed(t, nl, "uvdemo")
	require.Equal(t, "9.9.9", root.GetVersion())
	require.Equal(t, "pkg:pypi/uvdemo@9.9.9", root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
	require.Len(t, root.GetExternalReferences(), 1)
	require.Equal(t, "abc123", root.GetExternalReferences()[0].GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()

	index, err := (&code.Indexer{}).CatalogDirectories("testdata")
	require.NoError(t, err)
	locations, err := New().FindCodeBases(index)
	require.NoError(t, err)
	require.Len(t, locations, 7)
}

// TestExtractGenericPlatform covers the generic Platform of the decomposer
// options: the driver's own setting outranks it, and either reaches the
// marker evaluation.
func TestExtractGenericPlatform(t *testing.T) {
	t.Parallel()

	// The generic platform alone steers the extraction: windows keeps the
	// win32-only edge.
	opts := &api.DecomposerOptions{Platform: "windows/amd64"}
	opts.SetDriverOptions(New(), &Options{PythonVersion: "3.12"})
	nl := extract(t, "simple", opts)
	nodeNamed(t, nl, "colorama")

	// The driver's own platform wins over the generic one.
	opts = &api.DecomposerOptions{Platform: "windows/amd64"}
	opts.SetDriverOptions(New(), &Options{Platform: "linux/amd64", PythonVersion: "3.12"})
	nl = extract(t, "simple", opts)
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "colorama", n.GetName())
	}
}

// TestExtractWorkspace reads a uv workspace: two members, both the
// project's own, one depending on the other.
func TestExtractWorkspace(t *testing.T) {
	t.Parallel()

	nl := extract(t, "workspace", linuxOpts(t, "3.12"))

	// Both members root the graph.
	require.Len(t, nl.GetRootElements(), 2)
	uvws := nodeNamed(t, nl, "uvws")
	liba := nodeNamed(t, nl, "liba")
	require.Contains(t, nl.GetRootElements(), uvws.GetId())
	require.Contains(t, nl.GetRootElements(), liba.GetId())

	// The member edge resolves to the member, exactly once, and the
	// member keeps its own subtree.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, uvws, liba))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, uvws, nodeNamed(t, nl, "click")))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, liba, nodeNamed(t, nl, "idna")))

	// Each member has its own version and purl.
	require.Equal(t, "0.1.0", uvws.GetVersion())
	require.Equal(t, "0.2.0", liba.GetVersion())
	require.Equal(t, "pkg:pypi/liba@0.2.0",
		liba.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
}

// TestExtractGitDependency reads a lock whose dependency comes from a git
// repository rather than the index.
func TestExtractGitDependency(t *testing.T) {
	t.Parallel()

	nl := extract(t, "gitdep", linuxOpts(t, "3.12"))

	dotenv := nodeNamed(t, nl, "python-dotenv")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, nodeNamed(t, nl, "uvgit"), dotenv))

	// The source records where it comes from, down to the resolved commit
	// in the URL's fragment.
	require.Contains(t, dotenv.GetUrlDownload(), "github.com/theskumar/python-dotenv")
	require.Len(t, dotenv.GetExternalReferences(), 1)
	ref := dotenv.GetExternalReferences()[0]
	require.Equal(t, sbom.ExternalReference_VCS, ref.GetType())
	require.Contains(t, ref.GetUrl(), "#eaf2a9129ccec6febda0f741eb3bb852c3f947bd")

	// There is no artifact, so there is nothing to hash: an empty hash is
	// honest, an invented one is not.
	require.Empty(t, dotenv.GetHashes())
}

// TestEnrichSkipsNonRegistry pins which packages the index may be asked
// about: a git dependency's installed content is not PyPI's artifact, even
// when a package of the same name exists there.
func TestEnrichSkipsNonRegistry(t *testing.T) {
	t.Parallel()

	lock, err := ReadLockfile("testdata/gitdep/uv.lock")
	require.NoError(t, err)
	env, err := NewEnvironment("linux", "amd64", "3.12")
	require.NoError(t, err)

	tb := newTreeBuilder(lock, env, &api.DecomposerOptions{})
	_, err = tb.build()
	require.NoError(t, err)
	require.Empty(t, tb.enrichable, "nothing in this lock came from the registry")
}

// TestExtractPoetry reads the codebase locked by Poetry 2.x (lock 2.1).
// The graph's roots and first edges come from the manifest: the lock has
// no entry for the project's own package.
func TestExtractPoetry(t *testing.T) {
	t.Parallel()

	nl := extract(t, "poetry", linuxOpts(t, "3.12"))

	root := nodeNamed(t, nl, "poetrydemo")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())
	require.Equal(t, "0.1.0", root.GetVersion())
	require.Equal(t, "pkg:pypi/poetrydemo@0.1.0",
		root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	// The manifest's directs, and the lock's transitives under them.
	requests := nodeNamed(t, nl, "requests")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, requests))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, nodeNamed(t, nl, "click")))
	for _, dep := range []string{"certifi", "charset-normalizer", "idna", "urllib3"} {
		require.True(t, hasEdge(nl, sbom.Edge_dependsOn, requests, nodeNamed(t, nl, dep)))
	}

	// The windows-only edge and the color extra are both out: this is
	// linux and extras were not asked for.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "colorama", n.GetName())
		require.NotEqual(t, "pytest", n.GetName())
	}

	// Hashes come from the lock's file lists, wheel-selected: requests
	// ships a universal wheel.
	require.NotEmpty(t, requests.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
}

func TestExtractPoetryWindows(t *testing.T) {
	t.Parallel()

	opts := &api.DecomposerOptions{}
	opts.SetDriverOptions(New(), &Options{Platform: "windows/amd64", PythonVersion: "3.12"})
	nl := extract(t, "poetry", opts)

	// click needs colorama on Windows: the edge's marker held, and the
	// package's own group marker (platform_system == "Windows" or the
	// color extra) holds too.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn,
		nodeNamed(t, nl, "click"), nodeNamed(t, nl, "colorama")))
}

func TestExtractPoetryDevAndOptional(t *testing.T) {
	t.Parallel()

	opts := linuxOpts(t, "3.12")
	opts.IncludeDev = true
	opts.IncludeOptional = true
	nl := extract(t, "poetry", opts)

	root := nodeNamed(t, nl, "poetrydemo")

	// The dev group walks from the manifest's group table.
	pytest := nodeNamed(t, nl, "pytest")
	require.True(t, hasEdge(nl, sbom.Edge_devDependency, root, pytest))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, pytest, nodeNamed(t, nl, "pluggy")))

	// The color extra names colorama, whose lock marker tests extra
	// membership: with the extras enabled it applies even on linux.
	require.True(t, hasEdge(nl, sbom.Edge_optionalDependency, root, nodeNamed(t, nl, "colorama")))

	// Python 3.12 still prunes the old-python backports.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "exceptiongroup", n.GetName())
	}
}

// TestExtractPoetryLegacy reads the codebase locked by Poetry 1.8 (lock
// 2.0), which records no group membership: walking each group from the
// manifest's declarations is what derives it.
func TestExtractPoetryLegacy(t *testing.T) {
	t.Parallel()

	nl := extract(t, "poetrylegacy", linuxOpts(t, "3.12"))
	root := nodeNamed(t, nl, "poetrylegacy")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, nodeNamed(t, nl, "click")))
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "iniconfig", n.GetName(), "the dev group was not asked for")
	}

	opts := linuxOpts(t, "3.12")
	opts.IncludeDev = true
	nl = extract(t, "poetrylegacy", opts)
	require.True(t, hasEdge(nl, sbom.Edge_devDependency,
		nodeNamed(t, nl, "poetrylegacy"), nodeNamed(t, nl, "iniconfig")))
}

// TestExtractDispatch pins which lockfile wins when a codebase has
// several: uv.lock is the one uv keeps current.
func TestExtractDispatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"uv.lock", "pyproject.toml"} {
		data, err := os.ReadFile(filepath.Join("testdata/simple", name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600)) //nolint:gosec // a temp dir and fixed fixture names
	}
	poetry, err := os.ReadFile("testdata/poetry/poetry.lock")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "poetry.lock"), poetry, 0o600)) //nolint:gosec // a temp dir

	opts := linuxOpts(t, "3.12")
	opts.WorkDir = dir
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	// The uv lock's project is uvdemo; the poetry manifest's would have
	// been poetrydemo.
	nodeNamed(t, nl, "uvdemo")

	// And a directory with no lockfile at all is not a codebase.
	opts.WorkDir = t.TempDir()
	_, err = New().Extract(opts)
	require.ErrorContains(t, err, "no supported Python lockfile")
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"os"
	"path/filepath"
	"strings"
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
	require.Len(t, locations, 9)
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

// TestExtractWorkspaceMemberOrder reads a workspace whose lock lists a
// member after the member that depends on it. The dependent is walked
// first and reaches the other before its turn as a root: it is still one
// node, a root, with its own extras and groups.
func TestExtractWorkspaceMemberOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(`version = 1
revision = 3
requires-python = ">=3.12"

[manifest]
members = [
    "app",
    "zlib-member",
]

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "zlib-member" },
]

[[package]]
name = "idna"
version = "3.18"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "zlib-member"
version = "0.2.0"
source = { editable = "packages/zlib-member" }
dependencies = [
    { name = "idna" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]
`), 0o600))

	opts := linuxOpts(t, "3.12")
	opts.WorkDir = dir
	opts.IncludeDev = true
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	// nodeNamed requires a single node of the name.
	app := nodeNamed(t, nl, "app")
	member := nodeNamed(t, nl, "zlib-member")
	require.Equal(t, []string{app.GetId(), member.GetId()}, nl.GetRootElements())
	require.Len(t, nl.GetNodes(), 4)

	// The member is related under its dependent and keeps its subtree,
	// each edge once, and its dev group, which only its own turn adds.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, app, member))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, member, nodeNamed(t, nl, "idna")))
	require.True(t, hasEdge(nl, sbom.Edge_devDependency, member, nodeNamed(t, nl, "pytest")))
	edges := 0
	for _, e := range nl.GetEdges() {
		edges += len(e.GetTo())
	}
	require.Equal(t, 3, edges)

	// It is one of the project's own packages wherever it was reached from.
	require.Equal(t, []sbom.Purpose{sbom.Purpose_APPLICATION}, member.GetPrimaryPurpose())
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

// TestExtractPoetrySeveralVersions reads a 2.0 lock holding two versions
// of one package, as Poetry writes when the version resolved differs by
// environment. The entries state no markers of their own, so the edge's
// constraint and the Python versions each supports tell them apart.
func TestExtractPoetrySeveralVersions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(`[project]
name = "severalapp"
version = "0.1.0"
requires-python = ">=3.7"
dependencies = ["libb", "direct>=2 ; python_version >= '3.9'", "direct<2 ; python_version < '3.9'", "bypython"]
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(`[[package]]
name = "bypython"
version = "1.0"
description = ""
optional = false
python-versions = ">=3.7,<3.9"
files = []

[[package]]
name = "bypython"
version = "2.0"
description = ""
optional = false
python-versions = ">=3.9"
files = []

[[package]]
name = "direct"
version = "1.9"
description = ""
optional = false
python-versions = ">=3.7"
files = []

[[package]]
name = "direct"
version = "2.1"
description = ""
optional = false
python-versions = ">=3.7"
files = []

[[package]]
name = "libb"
version = "1.0"
description = ""
optional = false
python-versions = ">=3.7"
files = []

[package.dependencies]
shared = [
    {version = "<2", markers = "python_version < \"3.9\""},
    {version = ">=2", markers = "python_version >= \"3.9\""},
]

[[package]]
name = "shared"
version = "1.5"
description = ""
optional = false
python-versions = ">=3.7"
files = []

[[package]]
name = "shared"
version = "2.5"
description = ""
optional = false
python-versions = ">=3.7"
files = []

[metadata]
lock-version = "2.0"
python-versions = ">=3.7"
content-hash = "abc"
`), 0o600))

	for _, tc := range []struct {
		python                   string
		shared, direct, bypython string
	}{
		{python: "3.12", shared: "2.5", direct: "2.1", bypython: "2.0"},
		{python: "3.8", shared: "1.5", direct: "1.9", bypython: "1.0"},
	} {
		t.Run(tc.python, func(t *testing.T) {
			t.Parallel()
			opts := linuxOpts(t, tc.python)
			opts.WorkDir = dir
			opts.Networking = api.NetworkDisabled
			nl, err := New().Extract(opts)
			require.NoError(t, err)

			root := nodeNamed(t, nl, "severalapp")
			libb := nodeNamed(t, nl, "libb")

			// nodeNamed requires one node of the name: the other version
			// is not in the graph.
			shared := nodeNamed(t, nl, "shared")
			require.Equal(t, tc.shared, shared.GetVersion(), "by the constraint on a lock edge")
			require.True(t, hasEdge(nl, sbom.Edge_dependsOn, libb, shared))

			direct := nodeNamed(t, nl, "direct")
			require.Equal(t, tc.direct, direct.GetVersion(), "by the constraint the manifest declares")
			require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, direct))

			bypython := nodeNamed(t, nl, "bypython")
			require.Equal(t, tc.bypython, bypython.GetVersion(), "by the Python versions each entry supports")
			require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, bypython))
		})
	}
}

// TestExtractPoetryLegacyConstraints reads a manifest in Poetry's legacy
// table, whose constraints are its own: caret and tilde ranges, and for a
// dependency that differs by environment a list of them, each restricted
// to Python versions or a platform. They choose among the versions a 2.0
// lock holds for one name.
func TestExtractPoetryLegacyConstraints(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(`[tool.poetry]
name = "legacyapp"
version = "0.1.0"
description = ""
authors = []

[tool.poetry.dependencies]
python = ">=3.7"
bypython = [
    {version = "^1.5", python = "<3.9"},
    {version = "^2.5", python = "^3.9"},
]
byplatform = [
    {version = "~1.0", platform = "linux"},
    {version = "~2.0", platform = "win32"},
]
ranged = "^2.0"
`), 0o600))

	entry := func(name, version string) string {
		return `[[package]]
name = "` + name + `"
version = "` + version + `"
description = ""
optional = false
python-versions = ">=3.7"
files = []

`
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(
		entry("byplatform", "1.0.3")+entry("byplatform", "2.0.1")+
			entry("bypython", "1.5.2")+entry("bypython", "2.5.0")+
			entry("ranged", "1.9.0")+entry("ranged", "2.3.0")+`[metadata]
lock-version = "2.0"
python-versions = ">=3.7"
content-hash = "abc"
`), 0o600))

	for _, tc := range []struct {
		name                string
		platform, python    string
		bypython, platform2 string
	}{
		{name: "linux, 3.12", platform: "linux/amd64", python: "3.12", bypython: "2.5.0", platform2: "1.0.3"},
		{name: "linux, 3.8", platform: "linux/amd64", python: "3.8", bypython: "1.5.2", platform2: "1.0.3"},
		{name: "windows, 3.12", platform: "windows/amd64", python: "3.12", bypython: "2.5.0", platform2: "2.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &api.DecomposerOptions{WorkDir: dir, Networking: api.NetworkDisabled}
			opts.SetDriverOptions(New(), &Options{Platform: tc.platform, PythonVersion: tc.python})
			nl, err := New().Extract(opts)
			require.NoError(t, err)

			// nodeNamed requires one node of the name: each dependency
			// is in the graph once, at the version meant for here.
			root := nodeNamed(t, nl, "legacyapp")
			for name, version := range map[string]string{
				"bypython":   tc.bypython,
				"byplatform": tc.platform2,
				"ranged":     "2.3.0",
			} {
				node := nodeNamed(t, nl, name)
				require.Equal(t, version, node.GetVersion(), name)
				require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, node), name)
			}
			require.Len(t, nl.GetNodes(), 4)
		})
	}
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

// TestExtractRequirementsCompiled reads a file written by uv pip compile:
// exact pins, hashes, and via annotations recording the tree.
func TestExtractRequirementsCompiled(t *testing.T) {
	t.Parallel()

	nl := extract(t, "requirements", linuxOpts(t, "3.12"))

	// The root borrows the directory's name: the format names no project.
	root := nodeNamed(t, nl, "requirements")
	require.Equal(t, []string{root.GetId()}, nl.GetRootElements())

	// The via annotations rebuild the tree: the direct requirements hang
	// off the root, the transitives under what pulled them in.
	requests := nodeNamed(t, nl, "requests")
	click := nodeNamed(t, nl, "click")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, requests))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, click))
	for _, dep := range []string{"certifi", "charset-normalizer", "idna", "urllib3"} {
		require.True(t, hasEdge(nl, sbom.Edge_dependsOn, requests, nodeNamed(t, nl, dep)),
			"%s should hang under requests", dep)
		require.False(t, hasEdge(nl, sbom.Edge_dependsOn, root, nodeNamed(t, nl, dep)),
			"%s should not hang off the root", dep)
	}

	// Pins become versions and purls.
	require.NotEmpty(t, requests.GetVersion())
	require.Equal(t, "pkg:pypi/requests@"+requests.GetVersion(),
		requests.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	// A compiled file lists every artifact's hash and does not say which
	// belongs to what, so picking one would be guessing: no hashes.
	require.Empty(t, requests.GetHashes())

	// The universal resolution's windows-only colorama is not here.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "colorama", n.GetName())
	}
}

// TestExtractRequirementsLineAnnotations reads a file compiled with
// pip-compile --annotation-style=line, where each via annotation ends the
// line of the entry it belongs to.
func TestExtractRequirementsLineAnnotations(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "lineapp")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(
		`#
# This file is autogenerated by pip-compile with Python 3.12
#
click==8.1.7              # via flask
flask==3.0.0              # via -r requirements.in
jinja2==3.1.2             # via flask
markupsafe==2.1.3         # via jinja2, werkzeug
requests==2.31.0          # pinned by hand
werkzeug==3.0.1 \
    --hash=sha256:90a285dc0e42ad56b34e696398b8122ee4c681833fb35b8334a095d82c56da10  # via flask
`), 0o600))

	opts := linuxOpts(t, "3.12")
	opts.WorkDir = dir
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	root := nodeNamed(t, nl, "lineapp")
	flask := nodeNamed(t, nl, "flask")
	jinja2 := nodeNamed(t, nl, "jinja2")
	werkzeug := nodeNamed(t, nl, "werkzeug")
	markupsafe := nodeNamed(t, nl, "markupsafe")
	requests := nodeNamed(t, nl, "requests")

	// Only what the annotations say was required directly, and the entry
	// whose comment is not an annotation, hang off the root.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, flask))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, requests))
	for _, dep := range []string{"click", "jinja2", "werkzeug"} {
		require.True(t, hasEdge(nl, sbom.Edge_dependsOn, flask, nodeNamed(t, nl, dep)),
			"%s should hang under flask", dep)
	}
	// A comma separates the parents of one entry.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, jinja2, markupsafe))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, werkzeug, markupsafe))
	for _, dep := range []string{"click", "jinja2", "werkzeug", "markupsafe"} {
		require.False(t, hasEdge(nl, sbom.Edge_dependsOn, root, nodeNamed(t, nl, dep)),
			"%s should not hang off the root", dep)
	}

	// The comment does not cost the entry its pin, nor its hash.
	require.Equal(t, "3.0.0", flask.GetVersion())
	require.Equal(t, "pkg:pypi/requests@2.31.0",
		requests.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
	require.Equal(t, "90a285dc0e42ad56b34e696398b8122ee4c681833fb35b8334a095d82c56da10",
		werkzeug.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
}

// TestExtractRequirementsComments reads a file where comments sit under
// entries: only a via annotation, in either of its forms, says what pulled
// an entry in. A comment of the author's names nothing, and neither does
// one that follows an include.
func TestExtractRequirementsComments(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "commented")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "common.txt"), []byte("idna==3.18\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(
		`# The web stack
requests==2.31.0
# flask
flask==3.0.0
    # via -r requirements.in
jinja2==3.1.2
    # via flask
    # markupsafe
markupsafe==2.1.3
    # via
    #   jinja2
    #   werkzeug
werkzeug==3.0.1
    # via flask

-r common.txt
# requests
`), 0o600))

	opts := linuxOpts(t, "3.12")
	opts.WorkDir = dir
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	root := nodeNamed(t, nl, "commented")
	flask := nodeNamed(t, nl, "flask")
	jinja2 := nodeNamed(t, nl, "jinja2")
	markupsafe := nodeNamed(t, nl, "markupsafe")
	requests := nodeNamed(t, nl, "requests")
	idna := nodeNamed(t, nl, "idna")

	// The comments naming flask and requests are not annotations: the
	// entries above them stay where they were declared.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, requests))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, flask, requests))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, idna))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, requests, idna))

	// The single form names one parent, and a comment after it is not a
	// second one.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, flask, jinja2))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, markupsafe, jinja2))

	// The list form names one per line.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, jinja2, markupsafe))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, nodeNamed(t, nl, "werkzeug"), markupsafe))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, root, markupsafe))
}

// TestExtractRequirementsViaKinds reads a compiled file whose annotations
// name the three things one can: the project, through its requirements
// file or its manifest; a package of this environment; and a package the
// file declares for another environment.
func TestExtractRequirementsViaKinds(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "viakinds")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(
		`flask==3.0.0
    # via -r requirements.in
jinja2==3.1.2
    # via
    #   -r requirements.in
    #   flask
click==8.1.7
    # via
    #   -c constraints.txt
    #   flask
tomli==2.0.1
    # via viakinds (pyproject.toml)
pywin32==306 ; sys_platform == "win32"
    # via -r requirements.in
pywin32-ctypes==0.2.2
    # via pywin32
winhelper==1.0.0
    # via pywin32-ctypes
shared==1.0.0
    # via
    #   pywin32
    #   flask
`), 0o600))

	opts := linuxOpts(t, "3.12")
	opts.WorkDir = dir
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	root := nodeNamed(t, nl, "viakinds")
	flask := nodeNamed(t, nl, "flask")
	jinja2 := nodeNamed(t, nl, "jinja2")
	click := nodeNamed(t, nl, "click")
	shared := nodeNamed(t, nl, "shared")

	// Required by the project and by a package: an edge from each.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, jinja2))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, flask, jinja2))

	// A constraints file requires nothing: the package's edge is enough.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, flask, click))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, root, click))

	// The project's manifest is the project.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, nodeNamed(t, nl, "tomli")))

	// A parent for another environment gives no edge, and does not send
	// the entry to the root when it has another.
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, flask, shared))
	require.False(t, hasEdge(nl, sbom.Edge_dependsOn, root, shared))

	// With no parent left in this environment the entry is not in it
	// either, and neither is what only it pulls in.
	for _, n := range nl.GetNodes() {
		require.NotContains(t, []string{"pywin32", "pywin32-ctypes", "winhelper"}, n.GetName())
	}
	require.Len(t, nl.GetNodes(), 6)

	// On the platform the parent is for, the chain is there.
	opts = &api.DecomposerOptions{WorkDir: dir, Platform: "windows/amd64", Networking: api.NetworkDisabled}
	nl, err = New().Extract(opts)
	require.NoError(t, err)
	pywin32 := nodeNamed(t, nl, "pywin32")
	ctypes := nodeNamed(t, nl, "pywin32-ctypes")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, nodeNamed(t, nl, "viakinds"), pywin32))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, pywin32, ctypes))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, ctypes, nodeNamed(t, nl, "winhelper")))
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, pywin32, nodeNamed(t, nl, "shared")))
}

// TestExtractRequirementsLoose reads a hand-written file: partial pins, a
// git reference, an include, and no via annotations.
func TestExtractRequirementsLoose(t *testing.T) {
	t.Parallel()

	nl := extract(t, "requirementsloose", linuxOpts(t, "3.12"))
	root := nodeNamed(t, nl, "requirementsloose")

	// No annotations: everything hangs off the root.
	requests := nodeNamed(t, nl, "requests")
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, requests))

	// An unpinned range is a constraint, not a version: the node says so.
	click := nodeNamed(t, nl, "click")
	require.Empty(t, click.GetVersion())
	require.Equal(t, "pkg:pypi/click",
		click.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])

	// The windows-only entry is marker-pruned,
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "colorama", n.GetName())
	}

	// the include was followed,
	require.True(t, hasEdge(nl, sbom.Edge_dependsOn, root, nodeNamed(t, nl, "idna")))

	// the git reference keeps its URL,
	dotenv := nodeNamed(t, nl, "python-dotenv")
	require.Contains(t, dotenv.GetUrlDownload(), "git+https://github.com/theskumar/python-dotenv")
	require.Len(t, dotenv.GetExternalReferences(), 1)

	// and a lone hash identifies its entry's content.
	require.Equal(t, strings.Repeat("a", 64),
		nodeNamed(t, nl, "singlehash").GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	// The editable local package declared nothing, and neither did the
	// bare references: a path or URL names content, not a package. In
	// particular no node called "https" appears, which a naive parse of a
	// bare URL yields.
	for _, n := range nl.GetNodes() {
		require.NotEqual(t, "local-package", n.GetName())
		require.NotEqual(t, "https", n.GetName())
		require.NotEqual(t, "somepkg", n.GetName())
		require.NotContains(t, n.GetName(), "/")
	}
}

// TestExtractRequirementsPrecedence pins the dispatch order: a lockfile
// always outranks a requirements file, which is usually exported from it.
func TestExtractRequirementsPrecedence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for src, dst := range map[string]string{
		"testdata/poetry/poetry.lock":                 "poetry.lock",
		"testdata/poetry/pyproject.toml":              "pyproject.toml",
		"testdata/requirementsloose/requirements.txt": "requirements.txt",
		"testdata/requirementsloose/common.txt":       "common.txt",
	} {
		data, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, dst), data, 0o600)) //nolint:gosec // a temp dir
	}

	opts := linuxOpts(t, "3.12")
	opts.WorkDir = dir
	opts.Networking = api.NetworkDisabled
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	nodeNamed(t, nl, "poetrydemo")
}

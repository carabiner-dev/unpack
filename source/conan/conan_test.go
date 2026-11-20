// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package conan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

func TestParseReference(t *testing.T) {
	t.Parallel()
	for raw, expected := range map[string]*Reference{
		"zlib/1.3.1": {Name: "zlib", Version: "1.3.1"},
		"zlib/1.3.1#f52e03ae3d251dec704634230cd806a2%1708593606.497": {
			Name: "zlib", Version: "1.3.1", Revision: "f52e03ae3d251dec704634230cd806a2",
		},
		"zlib/1.2.13#revision1": {Name: "zlib", Version: "1.2.13", Revision: "revision1"},
		"internal/2.0@acme/stable#4524fcdd41f33e8df88ece6e755a5dcc%1650538915.154": {
			Name: "internal", Version: "2.0", User: "acme", Channel: "stable",
			Revision: "4524fcdd41f33e8df88ece6e755a5dcc",
		},
		"pkg/1.0@user":       {Name: "pkg", Version: "1.0", User: "user"},
		"pkg/1.0@_/_":        {Name: "pkg", Version: "1.0"},
		"  poco/1.9.4  ":     {Name: "poco", Version: "1.9.4"},
		"poco/[>1.0 <1.9]":   {Name: "poco", Range: ">1.0 <1.9"},
		"pkg/[~2.5]@me/dev":  {Name: "pkg", Range: "~2.5", User: "me", Channel: "dev"},
		"pkg/cci.20230125":   {Name: "pkg", Version: "cci.20230125"},
		"lib/1.0.0-rc.1+b.2": {Name: "lib", Version: "1.0.0-rc.1+b.2"},
	} {
		ref, err := ParseReference(raw)
		require.NoError(t, err, raw)
		require.Equal(t, expected, ref, raw)
	}

	for _, raw := range []string{"", "zlib", "zlib/", "/1.0", "zlib/[>=1.2", "zlib/@user/channel", "#rev"} {
		_, err := ParseReference(raw)
		require.Error(t, err, raw)
	}
}

func TestReadLock(t *testing.T) {
	t.Parallel()
	lock, err := ReadLock("testdata/locked/conan.lock")
	require.NoError(t, err)
	require.Equal(t, "0.5", lock.Version)
	require.Len(t, lock.Requires, 7)
	require.Len(t, lock.BuildRequires, 2)
	require.Len(t, lock.PythonRequires, 1)
	require.Equal(t, "acme", lock.Requires[4].User)
	require.Empty(t, lock.Requires[6].Revision)

	_, err = ParseLock([]byte(legacyLock))
	require.ErrorIs(t, err, ErrLegacyLockfile)

	// A lockfile made to lock binaries pairs a reference with its
	// package ids, and one may list configuration packages.
	lock, err = ParseLock([]byte(`{"version": "0.5",
		"requires": [
			["zlib/1.3.1#f52e03ae3d251dec704634230cd806a2%1708593606.497", {"pid1": "prev1", "pid2": null}],
			"fmt/10.2.1"
		],
		"config_requires": ["myconf/1.0#aaaa%1.0"],
		"overrides": {"zlib/*": ["zlib/1.3.1"]}}`))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"pid1": "prev1", "pid2": ""}, lock.Requires[0].Packages)
	require.Equal(t, "f52e03ae3d251dec704634230cd806a2", lock.Requires[0].Revision)
	require.Nil(t, lock.Requires[1].Packages)
	require.Equal(t, "myconf", lock.ConfigRequires[0].Name)

	_, err = ParseLock([]byte(`{"version": "0.5", "requires": [42]}`))
	require.Error(t, err)
	_, err = ParseLock([]byte(`{"version": "0.5", "requires": [[]]}`))
	require.Error(t, err)

	_, err = ParseLock([]byte(`{"version": "0.5", "requires": ["notareference"]}`))
	require.Error(t, err)
	_, err = ParseLock([]byte(`not json`))
	require.Error(t, err)

	// A lockfile that locks nothing is one all the same.
	lock, err = ParseLock([]byte(`{"version": "0.5", "requires": [], "build_requires": [], "python_requires": []}`))
	require.NoError(t, err)
	require.Empty(t, lock.Requires)
}

func TestParseManifest(t *testing.T) {
	t.Parallel()
	manifest, err := ReadManifest("testdata/locked/conanfile.txt")
	require.NoError(t, err)

	names := func(refs []*Reference) []string {
		out := make([]string, 0, len(refs))
		for _, ref := range refs {
			out = append(out, ref.Name)
		}
		return out
	}
	// The comment, and the sections that configure the build, name no
	// package.
	require.Equal(t, []string{"zlib", "openssl", "fmt", "internal"}, names(manifest.Requires))
	require.Equal(t, []string{"cmake"}, names(manifest.ToolRequires))
	require.Equal(t, []string{"catch2"}, names(manifest.TestRequires))
	require.Equal(t, ">=1.2 <2", manifest.Requires[0].Range)

	// Conan 1's name for tool requirements.
	manifest, err = ParseManifest([]byte("[build_requires]\ncmake/3.20.0\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"cmake"}, names(manifest.ToolRequires))

	_, err = ParseManifest([]byte("[requires]\nnot a reference\n"))
	require.ErrorContains(t, err, "line 2")
}

// legacyLock is a lockfile as Conan 1 wrote them.
const legacyLock = `{
 "graph_lock": {
  "nodes": {
   "0": {"ref": "pkgb/0.1@user/testing", "requires": ["1"], "path": "conanfile.py", "context": "host"},
   "1": {"ref": "pkga/0.1@user/testing", "package_id": "5ab84d6acfe1f23c4fae0ab88f26e3a396351ac9", "context": "host"}
  },
  "revisions_enabled": false
 },
 "version": "0.4",
 "profile_host": "[settings]\n"
}`

// TestPackageProperties checks the binaries a lockfile pins are on the
// node, in a stable order.
func TestPackageProperties(t *testing.T) {
	t.Parallel()
	node := packageNode(&Reference{
		Name: "zlib", Version: "1.3.1", Revision: "rrev",
		Packages: map[string]string{"pid2": "", "pid1": "prev1"},
	})
	require.Equal(t, []*sbom.Property{
		{Name: PropertyRevision, Data: "rrev"},
		{Name: PropertyPackageID, Data: "pid1"},
		{Name: PropertyPackageRevision, Data: "pid1#prev1"},
		{Name: PropertyPackageID, Data: "pid2"},
	}, node.GetProperties())
}

type edge struct {
	kind sbom.Edge_Type
	purl string
}

func extract(t *testing.T, dir string, opts *api.DecomposerOptions) (root *sbom.Node, edges map[string]edge, nodes map[string]*sbom.Node) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)

	byID := map[string]*sbom.Node{}
	nodes = map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
		nodes[node.GetName()] = node
	}
	edges = map[string]edge{}
	for _, e := range nl.GetEdges() {
		require.Equal(t, roots[0].GetId(), e.GetFrom(), "the graph is flat")
		for _, to := range e.GetTo() {
			node := byID[to]
			edges[node.GetName()] = edge{e.GetType(), string(node.Purl())}
		}
	}
	return roots[0], edges, nodes
}

func TestExtractLocked(t *testing.T) {
	t.Parallel()

	root, edges, nodes := extract(t, "testdata/locked", &api.DecomposerOptions{Version: "v1.0.0", CommitHash: "abc"})
	require.Equal(t, "locked", root.GetName())
	require.Equal(t, "pkg:generic/locked@v1.0.0", string(root.Purl()))
	require.Len(t, root.GetExternalReferences(), 1)

	// What the project is built from. The test and build requirements
	// wait for their flags; catch2 is in the lock's requires and the
	// manifest says it is for the tests.
	require.Equal(t, map[string]edge{
		"zlib":     {sbom.Edge_dependsOn, "pkg:conan/zlib@1.3.1?rrev=f52e03ae3d251dec704634230cd806a2"},
		"openssl":  {sbom.Edge_dependsOn, "pkg:conan/openssl@3.2.1?rrev=39bd48ed31f1f3fbdcd75a0648aaedcf"},
		"fmt":      {sbom.Edge_dependsOn, "pkg:conan/fmt@10.2.1?rrev=9199a7a0611866dea5c8849a77467b25"},
		"internal": {sbom.Edge_dependsOn, "pkg:conan/internal@2.0?channel=stable&rrev=4524fcdd41f33e8df88ece6e755a5dcc&user=acme"},
		"pinned":   {sbom.Edge_dependsOn, "pkg:conan/pinned@1.1"},
	}, edges)

	// The version is the lock's, whatever range the manifest asks for,
	// and of two revisions of a version the first listed is kept.
	require.Equal(t, "1.3.1", nodes["zlib"].GetVersion())
	require.Len(t, nodes["zlib"].GetProperties(), 1)
	require.Equal(t, PropertyRevision, nodes["zlib"].GetProperties()[0].GetName())
	require.Empty(t, nodes["zlib"].GetHashes(), "a recipe revision is no hash of the package")
	require.Empty(t, nodes["pinned"].GetProperties())

	_, edges, _ = extract(t, "testdata/locked", &api.DecomposerOptions{IncludeDev: true, IncludeBuild: true})
	require.Len(t, edges, 9)
	require.Equal(t, sbom.Edge_devDependency, edges["catch2"].kind)
	require.Equal(t, sbom.Edge_buildDependency, edges["cmake"].kind)
	require.Equal(t, sbom.Edge_buildDependency, edges["ninja"].kind)
	require.Equal(t, sbom.Edge_buildDependency, edges["pytools"].kind)
	require.Equal(t, "pkg:conan/cmake@3.28.1?rrev=92f79424d7b65b12a84a2180866c3a78", edges["cmake"].purl)
}

// TestExtractManifestOnly checks a project with no lockfile is read from
// what its manifest asks for: exact where it pins, a range where it does
// not.
func TestExtractManifestOnly(t *testing.T) {
	t.Parallel()
	_, edges, nodes := extract(t, "testdata/manifest", &api.DecomposerOptions{IncludeDev: true, IncludeBuild: true})
	require.Equal(t, map[string]edge{
		"poco":    {sbom.Edge_dependsOn, "pkg:conan/poco@1.9.4"},
		"zlib":    {sbom.Edge_dependsOn, "pkg:conan/zlib"},
		"boost":   {sbom.Edge_dependsOn, "pkg:conan/boost@1.70.0?rrev=revision2"},
		"private": {sbom.Edge_dependsOn, "pkg:conan/private@1.0?channel=testing&user=team"},
		"cmake":   {sbom.Edge_buildDependency, "pkg:conan/cmake@3.28.1"},
		"gtest":   {sbom.Edge_devDependency, "pkg:conan/gtest@1.14.0"},
	}, edges)

	require.Empty(t, nodes["zlib"].GetVersion())
	require.Equal(t, []*sbom.Property{{Name: PropertyRange, Data: ">1.0 <1.9"}}, nodes["zlib"].GetProperties())

	_, edges, _ = extract(t, "testdata/manifest", &api.DecomposerOptions{})
	require.Len(t, edges, 4)
}

func TestExtractErrors(t *testing.T) {
	t.Parallel()
	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.ErrorContains(t, err, "no conan.lock or conanfile.txt")
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add("both", LockFile)
	index.Add("both", ManifestFile)
	index.Add("locked", LockFile)
	index.Add("manifest", ManifestFile)
	// A recipe in Python and no lockfile: nothing to read.
	index.Add("python", "conanfile.py")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"both", "locked", "manifest"}, found)
}

func TestParseLegacyLock(t *testing.T) {
	t.Parallel()
	lock, err := ParseLegacyLock([]byte(legacyLock))
	require.NoError(t, err)
	require.Equal(t, "0.4", lock.Version)
	require.Len(t, lock.Nodes, 2)

	// The root is the node no other requires, here a package itself.
	root, err := lock.Root()
	require.NoError(t, err)
	require.Equal(t, "0", root.ID)
	require.Equal(t, "pkgb", root.Ref.Name)
	require.Equal(t, []string{"1"}, root.Requires)
	require.Equal(t, "5ab84d6acfe1f23c4fae0ab88f26e3a396351ac9", lock.Nodes["1"].PackageID)

	for name, data := range map[string]string{
		"not json":         `nope`,
		"no nodes":         `{"graph_lock": {"nodes": {}}, "version": "0.4"}`,
		"a lock bundle":    `{"lock_bundle": {"app/1.0": {"packages": []}}}`,
		"a missing node":   `{"graph_lock": {"nodes": {"0": {"requires": ["7"]}}}}`,
		"a bad reference":  `{"graph_lock": {"nodes": {"0": {"ref": "nothing"}}}}`,
		"two roots":        `{"graph_lock": {"nodes": {"0": {"ref": "a/1"}, "1": {"ref": "b/1"}}}}`,
		"a cycle, no root": `{"graph_lock": {"nodes": {"0": {"requires": ["1"]}, "1": {"requires": ["0"]}}}}`,
	} {
		_, err := ParseLegacyLock([]byte(data))
		require.ErrorIs(t, err, ErrLegacyGraph, name)
	}
}

// graph returns the edges of an extraction as "from -> to" by name, with
// their types.
func graph(t *testing.T, dir string, opts *api.DecomposerOptions) (edges map[string]sbom.Edge_Type, nodes map[string]*sbom.Node) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	byID := map[string]*sbom.Node{}
	nodes = map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
		nodes[node.GetName()] = node
	}
	require.Len(t, nodes, len(byID), "a package is one node")
	edges = map[string]sbom.Edge_Type{}
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			edges[byID[e.GetFrom()].GetName()+" -> "+byID[to].GetName()] = e.GetType()
		}
	}
	return edges, nodes
}

// TestExtractLegacy checks a Conan 1 lockfile gives its graph: the edges
// it records, and not a flat list.
func TestExtractLegacy(t *testing.T) {
	t.Parallel()

	edges, nodes := graph(t, "testdata/legacy", &api.DecomposerOptions{})
	require.Equal(t, map[string]sbom.Edge_Type{
		"legacy -> applib":  sbom.Edge_dependsOn,
		"legacy -> openssl": sbom.Edge_dependsOn,
		"applib -> zlib":    sbom.Edge_dependsOn,
		"openssl -> zlib":   sbom.Edge_dependsOn,
	}, edges)

	require.Equal(t,
		"pkg:conan/applib@1.0?channel=stable&rrev=4524fcdd41f33e8df88ece6e755a5dcc&user=acme",
		string(nodes["applib"].Purl()))
	require.Equal(t, []*sbom.Property{
		{Name: PropertyRevision, Data: "4524fcdd41f33e8df88ece6e755a5dcc"},
		{Name: PropertyPackageID, Data: "5ab84d6acfe1f23c4fae0ab88f26e3a396351ac9"},
		{Name: PropertyPackageRevision, Data: "5ab84d6acfe1f23c4fae0ab88f26e3a396351ac9#83c38d3b4e5f1b8450434436eec31b00"},
	}, nodes["applib"].GetProperties())
	// A package revision of "0" is Conan 1 saying there is none.
	require.Equal(t, []*sbom.Property{
		{Name: PropertyPackageID, Data: "6af9cc7cb931c5ad942174fd7838eb655717c709"},
	}, nodes["zlib"].GetProperties())

	// The tests' and the build's requirements, each with what it brings:
	// the recipe tooling of a package, the build tool and what the tool
	// requires, which is the zlib already there.
	edges, _ = graph(t, "testdata/legacy", &api.DecomposerOptions{IncludeDev: true, IncludeBuild: true})
	require.Equal(t, map[string]sbom.Edge_Type{
		"legacy -> applib":  sbom.Edge_dependsOn,
		"legacy -> openssl": sbom.Edge_dependsOn,
		"applib -> zlib":    sbom.Edge_dependsOn,
		"openssl -> zlib":   sbom.Edge_dependsOn,
		"legacy -> catch2":  sbom.Edge_devDependency,
		"legacy -> cmake":   sbom.Edge_buildDependency,
		"cmake -> zlib":     sbom.Edge_dependsOn,
		"applib -> pytools": sbom.Edge_buildDependency,
	}, edges)
}

// TestExtractUnreadableLegacy checks a Conan 1 lockfile that cannot be
// made out is left aside, and the project read from its manifest or, with
// none, as a project with nothing known of it.
func TestExtractUnreadableLegacy(t *testing.T) {
	t.Parallel()
	const bundle = `{"lock_bundle": {"app/1.0": {"packages": []}}}`

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, LockFile), []byte(bundle), 0o600))
	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: dir})
	require.NoError(t, err)
	require.Len(t, nl.GetNodes(), 1)

	require.NoError(t, os.WriteFile(filepath.Join(dir, ManifestFile), []byte("[requires]\nzlib/1.3.1\n"), 0o600))
	nl, err = New().Extract(&api.DecomposerOptions{WorkDir: dir})
	require.NoError(t, err)
	require.Len(t, nl.GetNodes(), 2)

	// A lockfile that is no JSON at all is still an error: that is a
	// broken file, not another format.
	require.NoError(t, os.WriteFile(filepath.Join(dir, LockFile), []byte("not json"), 0o600))
	_, err = New().Extract(&api.DecomposerOptions{WorkDir: dir})
	require.Error(t, err)
}

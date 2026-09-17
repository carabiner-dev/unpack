// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rustbinary

import (
	"bytes"
	"compress/zlib"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact/internal/exetest"
	"github.com/carabiner-dev/unpack/source/rust"
)

// withDeps is the record cargo-auditable 0.7 embedded in a crate with one
// runtime dependency (either) and one build dependency (cc), verbatim.
const withDeps = `{
 "packages": [
  {"name": "cc", "version": "1.4.6", "source": "crates.io", "kind": "build", "dependencies": [2, 3]},
  {"name": "either", "version": "1.18.0", "source": "crates.io"},
  {"name": "find-msvc-tools", "version": "0.1.12", "source": "crates.io", "kind": "build"},
  {"name": "shlex", "version": "2.0.1", "source": "crates.io", "kind": "build"},
  {"name": "withdeps", "version": "0.1.0", "source": "local", "dependencies": [0, 1], "root": true}
 ],
 "format": 1
}`

func compress(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write([]byte(data))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func purlOf(n *sbom.Node) string {
	return n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
}

func byPurl(nl *sbom.NodeList, purl string) *sbom.Node {
	nodes := nl.GetNodesByIdentifier("purl", purl)
	if len(nodes) == 0 {
		return nil
	}
	return nodes[0]
}

// edges returns "from -> to" pairs by purl with the edge type.
func edges(nl *sbom.NodeList) map[string]sbom.Edge_Type {
	out := map[string]sbom.Edge_Type{}
	for _, e := range nl.GetEdges() {
		from := purlOf(nl.GetNodeByID(e.GetFrom()))
		for _, to := range e.GetTo() {
			out[from+" -> "+purlOf(nl.GetNodeByID(to))] = e.GetType()
		}
	}
	return out
}

func TestTraits(t *testing.T) {
	t.Parallel()
	d := New()
	assert.Equal(t, "rustbinary", d.Name())
	assert.ElementsMatch(t, []string{"image", "system"}, d.DefaultSubjects())
	assert.Nil(t, d.Requirements(nil))
	assert.Equal(t, rust.New().DefaultOptions(), d.DefaultOptions())
	assert.True(t, d.Matches(nil, []byte("\x7fELF\x02\x01\x01")))
	assert.False(t, d.Matches(nil, []byte("#!/bin/sh")))
}

func TestDecodeRecord(t *testing.T) {
	t.Parallel()

	info, err := DecodeRecord(compress(t, withDeps))
	require.NoError(t, err)
	assert.Equal(t, 1, info.Format)
	require.Len(t, info.Packages, 5)
	assert.Equal(t, Package{Name: "cc", Version: "1.4.6", Source: "crates.io", Kind: "build", Dependencies: []int{2, 3}}, info.Packages[0])
	assert.True(t, info.Packages[4].Root)

	for name, data := range map[string][]byte{
		"not compressed": []byte(withDeps),
		"not json":       compress(t, "nope"),
		"no packages":    compress(t, `{"packages": []}`),
		"empty":          {},
	} {
		_, err := DecodeRecord(data)
		require.Error(t, err, name)
	}

	// A record inflating past the bound is rejected rather than read.
	huge := `{"packages":[{"name":"a","version":"1.0.0","source":"local","root":true}]` +
		strings.Repeat(" ", maxRecordSize) + "}"
	_, err = DecodeRecord(compress(t, huge))
	require.ErrorContains(t, err, "inflates past")
}

func TestBuildNodeList(t *testing.T) {
	t.Parallel()
	info, err := DecodeRecord(compress(t, withDeps))
	require.NoError(t, err)

	t.Run("runtime only by default", func(t *testing.T) {
		t.Parallel()
		nl, cratesIO, err := BuildNodeList(info, nil)
		require.NoError(t, err)

		roots := nl.GetRootElements()
		require.Len(t, roots, 1)
		root := nl.GetNodeByID(roots[0])
		assert.Equal(t, "withdeps", root.GetName())
		assert.Equal(t, "0.1.0", root.GetVersion())
		assert.Equal(t, "pkg:cargo/withdeps@0.1.0", purlOf(root))
		assert.Equal(t, []sbom.Purpose{sbom.Purpose_APPLICATION}, root.GetPrimaryPurpose())
		props := map[string]string{}
		for _, p := range root.GetProperties() {
			props[p.GetName()] = p.GetData()
		}
		assert.Equal(t, "1", props[PropertyFormat])
		assert.Equal(t, "local", props[PropertySource])

		// The build dependency and everything only it pulls in are gone.
		assert.Len(t, nl.GetNodes(), 2)
		either := byPurl(nl, "pkg:cargo/either@1.18.0")
		require.NotNil(t, either)
		assert.Equal(t, "https://crates.io/api/v1/crates/either/1.18.0/download", either.GetUrlDownload())
		assert.Empty(t, either.GetProperties(), "crates.io packages carry no source property")
		assert.Nil(t, byPurl(nl, "pkg:cargo/cc@1.4.6"))
		assert.Nil(t, byPurl(nl, "pkg:cargo/shlex@2.0.1"))

		assert.Equal(t, map[string]sbom.Edge_Type{
			"pkg:cargo/withdeps@0.1.0 -> pkg:cargo/either@1.18.0": sbom.Edge_dependsOn,
		}, edges(nl))

		// Only crates.io packages are offered for enrichment, and the
		// root is not among them.
		assert.Equal(t, map[rust.PackageKey]*sbom.Node{{Name: "either", Version: "1.18.0"}: either}, cratesIO)
	})

	t.Run("build dependencies on request", func(t *testing.T) {
		t.Parallel()
		nl, cratesIO, err := BuildNodeList(info, &api.DecomposerOptions{IncludeBuild: true})
		require.NoError(t, err)
		assert.Len(t, nl.GetNodes(), 5)
		assert.Len(t, cratesIO, 4)
		assert.Equal(t, map[string]sbom.Edge_Type{
			"pkg:cargo/withdeps@0.1.0 -> pkg:cargo/either@1.18.0":    sbom.Edge_dependsOn,
			"pkg:cargo/withdeps@0.1.0 -> pkg:cargo/cc@1.4.6":         sbom.Edge_buildDependency,
			"pkg:cargo/cc@1.4.6 -> pkg:cargo/find-msvc-tools@0.1.12": sbom.Edge_buildDependency,
			"pkg:cargo/cc@1.4.6 -> pkg:cargo/shlex@2.0.1":            sbom.Edge_buildDependency,
		}, edges(nl))
	})

	t.Run("version and commit overrides", func(t *testing.T) {
		t.Parallel()
		nl, _, err := BuildNodeList(info, &api.DecomposerOptions{Version: "v9.9.9", CommitHash: "abc123"})
		require.NoError(t, err)
		root := nl.GetNodeByID(nl.GetRootElements()[0])
		assert.Equal(t, "pkg:cargo/withdeps@v9.9.9", purlOf(root))
		require.Len(t, root.GetExternalReferences(), 1)
		assert.Equal(t, "abc123", root.GetExternalReferences()[0].GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
	})

	t.Run("shared and non-crates.io dependencies", func(t *testing.T) {
		t.Parallel()
		diamond := &VersionInfo{Packages: []Package{
			{Name: "app", Version: "1.0.0", Source: "local", Root: true, Dependencies: []int{1, 2}},
			{Name: "a", Version: "1.0.0", Source: "crates.io", Dependencies: []int{3}},
			{Name: "b", Version: "1.0.0", Source: "git", Dependencies: []int{3}},
			{Name: "shared", Version: "2.0.0", Source: "registry"},
			{Name: "orphan", Version: "1.0.0", Source: "crates.io"},
		}}
		nl, cratesIO, err := BuildNodeList(diamond, nil)
		require.NoError(t, err)
		assert.Len(t, nl.GetNodes(), 4, "shared once, the orphan never")
		assert.Nil(t, byPurl(nl, "pkg:cargo/orphan@1.0.0"))
		b := byPurl(nl, "pkg:cargo/b@1.0.0")
		require.NotNil(t, b)
		assert.Empty(t, b.GetUrlDownload())
		require.Len(t, b.GetProperties(), 1)
		assert.Equal(t, "git", b.GetProperties()[0].GetData())
		assert.Len(t, cratesIO, 1)
		assert.Len(t, edges(nl), 4)
	})

	t.Run("broken records", func(t *testing.T) {
		t.Parallel()
		_, _, err := BuildNodeList(&VersionInfo{Packages: []Package{{Name: "a", Version: "1"}}}, nil)
		require.ErrorContains(t, err, "no root")
		_, _, err = BuildNodeList(&VersionInfo{Packages: []Package{{Name: "a", Version: "1", Root: true, Dependencies: []int{7}}}}, nil)
		require.ErrorContains(t, err, "out of range")
	})
}

func TestExtractArtifact(t *testing.T) {
	t.Parallel()
	record := compress(t, withDeps)
	d := New()

	for name, build := range map[string]func(string, []byte) []byte{
		"elf": exetest.ELF, "pe": exetest.PE, "macho": exetest.MachO,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			exe := build(SectionName, record)
			nl, err := d.ExtractArtifact(bytes.NewReader(exe), "app", &api.DecomposerOptions{Networking: api.NetworkDisabled})
			require.NoError(t, err)
			require.NotNil(t, nl)
			assert.Equal(t, "withdeps", nl.GetNodeByID(nl.GetRootElements()[0]).GetName())
			assert.NotNil(t, byPurl(nl, "pkg:cargo/either@1.18.0"))
		})
	}

	t.Run("disowned", func(t *testing.T) {
		t.Parallel()
		for name, data := range map[string][]byte{
			"no record section": exetest.ELF(".text", []byte("code")),
			"not an executable": []byte("just some text, long enough to not be a short read at all"),
			"empty":             {},
		} {
			nl, err := d.ExtractArtifact(bytes.NewReader(data), name, nil)
			require.NoError(t, err, name)
			assert.Nil(t, nl, name)
		}
	})

	t.Run("broken record is an error", func(t *testing.T) {
		t.Parallel()
		_, err := d.ExtractArtifact(bytes.NewReader(exetest.ELF(SectionName, []byte("garbage"))), "app", nil)
		require.ErrorContains(t, err, "decoding the cargo-auditable record")
	})
}

func TestExtract(t *testing.T) {
	t.Parallel()
	d := New()
	_, err := d.Extract(nil)
	require.Error(t, err)
	_, err = d.Extract(&api.DecomposerOptions{WorkDir: "/nonexistent/binary"})
	require.Error(t, err)

	path := filepath.Join(t.TempDir(), "app")
	require.NoError(t, os.WriteFile(path, exetest.ELF(SectionName, compress(t, withDeps)), 0o600))
	nl, err := d.Extract(&api.DecomposerOptions{WorkDir: path, Networking: api.NetworkDisabled})
	require.NoError(t, err)
	assert.Equal(t, "withdeps", nl.GetNodeByID(nl.GetRootElements()[0]).GetName())
}

// TestRealCargoAuditable builds a crate with cargo-auditable, when it is
// installed, and reads the binary back. It is the check that the section
// name and encoding match what the tool writes today.
func TestRealCargoAuditable(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds a crate with cargo (drop -short to run)")
	}
	if err := exec.CommandContext(t.Context(), "cargo", "auditable", "--version").Run(); err != nil {
		t.Skipf("skipping: cargo-auditable is not available: %v", err)
	}

	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "cargo", args...) //nolint:gosec // fixed arguments
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "cargo %v:\n%s", args, out)
	}
	// No dependencies, so the build needs no network.
	run("new", "--bin", "--vcs", "none", "--quiet", "hello")
	dir = filepath.Join(dir, "hello")
	run("auditable", "build", "--release", "--quiet")

	exe := filepath.Join(dir, "target", "release", "hello")
	if _, err := os.Stat(exe + ".exe"); err == nil {
		exe += ".exe"
	}
	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: exe, Networking: api.NetworkDisabled})
	require.NoError(t, err)
	require.NotNil(t, nl, "the binary carries a cargo-auditable record")
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	assert.Equal(t, "hello", root.GetName())
	assert.Equal(t, "pkg:cargo/hello@0.1.0", purlOf(root))
}

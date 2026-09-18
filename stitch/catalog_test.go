// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	toolSHA256   = "aaaa000000000000000000000000000000000000000000000000000000000001"
	libbazSHA256 = "bbbb000000000000000000000000000000000000000000000000000000000002"
)

func loadTestCatalog(t *testing.T) *Catalog {
	t.Helper()
	c := NewCatalog()
	require.NoError(t, c.Load(filepath.Join("testdata", "supplements")))
	return c
}

func entryNames(entries []*Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Node.GetName())
	}
	return out
}

func TestCatalogLoad(t *testing.T) {
	t.Parallel()
	c := loadTestCatalog(t)

	sups := c.Supplements()
	require.Len(t, sups, 2, "the README is not a supplement")
	assert.Equal(t, []string{filepath.Join("testdata", "supplements", "README.txt")}, c.Unparsed())

	// Supplements load in walk order, each with its described components.
	assert.Equal(t, filepath.Join("testdata", "supplements", "libs.cdx.json"), sups[0].Source)
	assert.Equal(t, []string{"libbar"}, entryNames(sups[0].Entries))
	assert.Equal(t, filepath.Join("testdata", "supplements", "tool.spdx.json"), sups[1].Source)
	assert.Equal(t, []string{"tool"}, entryNames(sups[1].Entries))
	assert.Equal(t, []string{"libbar", "tool"}, entryNames(c.Entries()))
	assert.Equal(t, "https://example.com/sboms/tool#DOCUMENT", sups[1].Document.GetMetadata().GetId())

	// The entry is the document's own node, and the graph below it is
	// in the document's list.
	tool := sups[1].Entries[0]
	assert.Equal(t, "1.2.3", tool.Node.GetVersion())
	assert.Equal(t, toolSHA256, tool.Node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	assert.NotNil(t, sups[1].Document.GetNodeList().GetNodeByID(tool.ID()))
	assert.Len(t, sups[1].Document.GetNodeList().GetNodes(), 3)

	// Explicit files must parse; a directory tolerates strays.
	c2 := NewCatalog()
	require.NoError(t, c2.Load(filepath.Join("testdata", "supplements", "tool.spdx.json")))
	assert.Len(t, c2.Supplements(), 1)
	require.Error(t, c2.Load(filepath.Join("testdata", "supplements", "README.txt")))
	require.Error(t, c2.Load(filepath.Join("testdata", "nope")))
	// One bad path does not stop the others from loading.
	c3 := NewCatalog()
	err := c3.Load(filepath.Join("testdata", "nope"), filepath.Join("testdata", "supplements", "libs.cdx.json"))
	require.Error(t, err)
	assert.Len(t, c3.Supplements(), 1)
}

func TestCatalogMatch(t *testing.T) {
	t.Parallel()
	c := loadTestCatalog(t)

	t.Run("file by hash", func(t *testing.T) {
		t.Parallel()
		found := c.Match(file("usr/local/bin/tool", toolSHA256))
		assert.Equal(t, []string{"tool"}, entryNames(found), "a package entry describes a file with its hash")
	})

	t.Run("package by purl when no algorithm is shared", func(t *testing.T) {
		t.Parallel()
		found := c.Match(pkg("x", "pkg:generic/tool@1.2.3"))
		assert.Equal(t, []string{"tool"}, entryNames(found))

		// A SHA-1 on the node shares no algorithm with the entry's
		// SHA-256, so the purl still decides.
		n := pkg("x", "pkg:generic/tool@1.2.3")
		n.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA1): "s1"}
		assert.Equal(t, []string{"tool"}, entryNames(c.Match(n)))
	})

	t.Run("conflicting hash beats the purl", func(t *testing.T) {
		t.Parallel()
		n := pkg("x", "pkg:generic/tool@1.2.3", "cccc000000000000000000000000000000000000000000000000000000000003")
		assert.Empty(t, c.Match(n))
	})

	t.Run("entries without hashes match by purl only", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"libbar"}, entryNames(c.Match(pkg("x", "pkg:generic/libbar@3.1.0"))))
		assert.Equal(t, []string{"libbar"}, entryNames(c.Match(pkg("x", "pkg:generic/libbar@3.1.0", "anything"))),
			"the entry states no hash, so the node's cannot conflict")
	})

	t.Run("non-root components never match", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, c.Match(pkg("x", "pkg:generic/libbaz@0.9.0", libbazSHA256)))
		assert.Empty(t, c.Match(pkg("x", "pkg:generic/libfoo@2.0.0")))
	})

	t.Run("nothing", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, c.Match(pkg("x", "pkg:generic/other@1.0.0")))
		assert.Empty(t, c.Match(pkg("x", "")))
	})

	t.Run("several entries, catalog order, once each", func(t *testing.T) {
		t.Parallel()
		c := loadTestCatalog(t)
		// A second document describing the same tool by hash and purl.
		doc := &sbom.Document{NodeList: sbom.NewNodeList()}
		doc.GetNodeList().AddRootNode(pkg("again", "pkg:generic/tool@1.2.3", toolSHA256))
		c.Add("again.json", doc)

		found := c.Match(pkg("x", "pkg:generic/tool@1.2.3", toolSHA256))
		assert.Equal(t, []string{"tool", "again"}, entryNames(found))
	})
}

func TestCatalogUnused(t *testing.T) {
	t.Parallel()
	c := loadTestCatalog(t)
	assert.Equal(t, []string{"libbar", "tool"}, entryNames(c.Unused()))
	c.Match(pkg("x", "pkg:generic/libbar@3.1.0"))[0].Used = true
	assert.Equal(t, []string{"tool"}, entryNames(c.Unused()))
}

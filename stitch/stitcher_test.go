// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func propsOf(n *sbom.Node) map[string]string {
	out := map[string]string{}
	for _, p := range n.GetProperties() {
		out[p.GetName()] = p.GetData()
	}
	return out
}

func TestStitchFileGetsPackageAttached(t *testing.T) {
	t.Parallel()
	s := New(loadTestCatalog(t))
	bin := file("usr/local/bin/tool", toolSHA256)
	nl := graph([]*sbom.Node{pkg("image", "pkg:oci/img@sha256%3Aabc"), bin}, "image>usr/local/bin/tool")

	report, err := s.Stitch(nl)
	require.NoError(t, err)

	// The tool package hangs under the file, its dependencies below it,
	// and libbar, which the CycloneDX supplement describes, got that
	// supplement merged in: a chain across two documents.
	require.Len(t, report.Stitched, 2)
	assert.Equal(t, bin.GetId(), report.Stitched[0].NodeID)
	assert.Equal(t, "tool", report.Stitched[0].Entry.Node.GetName())
	assert.False(t, report.Stitched[0].Merged)
	assert.Equal(t, "libbar", report.Stitched[1].Entry.Node.GetName())
	assert.True(t, report.Stitched[1].Merged)

	assert.ElementsMatch(t, []string{"image", "usr/local/bin/tool", "tool", "libfoo", "libbar", "libbaz"}, names(nl.GetNodes()))
	assert.ElementsMatch(t, []string{
		"image>usr/local/bin/tool:dependsOn",
		"usr/local/bin/tool>tool:generatedFrom",
		"tool>libfoo:dependsOn", "libfoo>libbar:dependsOn",
		// CycloneDX lists components under the top one as well as in
		// the dependency graph, and protobom keeps both.
		"libbar>libbaz:dependsOn", "libbar>libbaz:contains",
	}, edgeSet(nl))
	assert.Equal(t, []string{"image"}, nl.GetRootElements())

	// Provenance lands on the nodes stitched onto.
	assert.Equal(t, filepath.Join("testdata", "supplements", "tool.spdx.json"), propsOf(bin)[PropertyStitchedFrom])
	require.Len(t, bin.GetExternalReferences(), 1)
	assert.Equal(t, sbom.ExternalReference_BOM, bin.GetExternalReferences()[0].GetType())
	assert.Equal(t, "https://example.com/sboms/tool#DOCUMENT", bin.GetExternalReferences()[0].GetUrl())
	libbar := nl.GetNodesByName("libbar")[0]
	assert.Equal(t, filepath.Join("testdata", "supplements", "libs.cdx.json"), propsOf(libbar)[PropertyStitchedFrom])
	assert.Equal(t, libbazSHA256, nl.GetNodesByName("libbaz")[0].GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	// Everything was used, nothing dropped.
	assert.Empty(t, s.Catalog.Unused())
	assert.Empty(t, report.Dropped)
}

func TestStitchPackageMerges(t *testing.T) {
	t.Parallel()
	s := New(loadTestCatalog(t))
	found := pkg("tool", "pkg:generic/tool@1.2.3")
	found.Version = "1.2.3-observed"
	nl := graph([]*sbom.Node{found})

	report, err := s.Stitch(nl)
	require.NoError(t, err)
	require.Len(t, report.Stitched, 2)
	assert.True(t, report.Stitched[0].Merged)

	// The found node kept its version and gained the supplement's hash
	// and license; the graph hangs directly off it.
	assert.Equal(t, "1.2.3-observed", found.GetVersion())
	assert.Equal(t, toolSHA256, found.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	assert.Equal(t, []string{"Apache-2.0"}, found.GetLicenses())
	assert.ElementsMatch(t, []string{"tool", "libfoo", "libbar", "libbaz"}, names(nl.GetNodes()))
	assert.Contains(t, edgeSet(nl), "tool>libfoo:dependsOn")
	assert.Equal(t, []string{found.GetId()}, nl.GetRootElements())
}

func TestStitchFileEntryUnderPackage(t *testing.T) {
	t.Parallel()
	c := NewCatalog()
	doc := &sbom.Document{NodeList: sbom.NewNodeList()}
	doc.GetNodeList().AddRootNode(file("tool.bin", toolSHA256))
	c.Add("files.json", doc)
	target := pkg("tool", "pkg:generic/tool@1.2.3", toolSHA256)
	nl := graph([]*sbom.Node{target})

	report, err := New(c).Stitch(nl)
	require.NoError(t, err)
	require.Len(t, report.Stitched, 1)
	assert.False(t, report.Stitched[0].Merged)
	assert.Equal(t, []string{"tool>tool.bin:contains"}, edgeSet(nl))
	assert.Equal(t, "files.json", target.GetExternalReferences()[0].GetUrl(), "no document id, the source stands in")
}

func TestStitchDedupesAcrossTargets(t *testing.T) {
	t.Parallel()
	s := New(loadTestCatalog(t))
	// Two copies of the same binary in one image.
	a, b := file("bin/tool", toolSHA256), file("opt/tool", toolSHA256)
	nl := graph([]*sbom.Node{pkg("image", "pkg:oci/img@sha256%3Aabc"), a, b}, "image>bin/tool", "image>opt/tool")

	report, err := s.Stitch(nl)
	require.NoError(t, err)
	assert.Len(t, report.Stitched, 4, "each file got the tool, each tool's libbar got the libs")

	// The files stay apart (different names, but the same hash: they are
	// the same component) -- dedupe collapses them too, and the two
	// copies of the supplement graph fold into one.
	assert.Len(t, report.Dropped, 5)
	assert.ElementsMatch(t, []string{"image", "bin/tool", "tool", "libfoo", "libbar", "libbaz"}, names(nl.GetNodes()))
	assert.ElementsMatch(t, []string{
		"image>bin/tool:dependsOn", "bin/tool>tool:generatedFrom",
		"tool>libfoo:dependsOn", "libfoo>libbar:dependsOn",
		"libbar>libbaz:dependsOn", "libbar>libbaz:contains",
	}, edgeSet(nl))

	t.Run("without dedupe", func(t *testing.T) {
		t.Parallel()
		s := New(loadTestCatalog(t))
		s.Options.NoDedupe = true
		nl := graph([]*sbom.Node{pkg("image", "pkg:oci/img@sha256%3Aabc"), file("bin/tool", toolSHA256), file("opt/tool", toolSHA256)}, "image>bin/tool", "image>opt/tool")
		report, err := s.Stitch(nl)
		require.NoError(t, err)
		assert.Empty(t, report.Dropped)
		assert.Len(t, nl.GetNodes(), 11)
	})
}

func TestStitchNeverAppliesWithinItself(t *testing.T) {
	t.Parallel()
	// A document describing a package whose dependency carries the same
	// purl as the root: naive chaining would stitch it forever.
	c := NewCatalog()
	doc := &sbom.Document{NodeList: sbom.NewNodeList()}
	root := pkg("self", "pkg:generic/self@1")
	doc.GetNodeList().AddRootNode(root)
	doc.GetNodeList().AddNode(pkg("twin", "pkg:generic/self@1"))
	doc.GetNodeList().MergeEdges([]*sbom.Edge{{From: "self", Type: sbom.Edge_dependsOn, To: []string{"twin"}}})
	c.Add("self.json", doc)

	nl := graph([]*sbom.Node{file("bin", "zzzz"), pkg("app", "pkg:generic/self@1")}, "bin>app")
	s := New(c)
	s.Options.NoDedupe = true
	report, err := s.Stitch(nl)
	require.NoError(t, err)
	assert.Len(t, report.Stitched, 1)
	assert.ElementsMatch(t, []string{"bin", "app", "twin"}, names(nl.GetNodes()))
}

func TestStitchNothingToDo(t *testing.T) {
	t.Parallel()
	s := New(loadTestCatalog(t))
	nl := graph([]*sbom.Node{pkg("other", "pkg:generic/other@1")})
	report, err := s.Stitch(nl)
	require.NoError(t, err)
	assert.Empty(t, report.Stitched)
	assert.Len(t, s.Catalog.Unused(), 2)

	report, err = New(nil).Stitch(nl)
	require.NoError(t, err)
	assert.Empty(t, report.Stitched)
	_, err = s.Stitch(nil)
	require.NoError(t, err)
}

// fakeUnpacker returns fixed lists.
type fakeUnpacker struct {
	lists []*sbom.NodeList
	err   error
	regs  int
}

func (f *fakeUnpacker) Extract(context.Context, api.DecomposableSubject) ([]*sbom.NodeList, error) {
	return f.lists, f.err
}
func (f *fakeUnpacker) RegisterDecomposer(api.Decomposer)   { f.regs++ }
func (f *fakeUnpacker) UnregisterDecomposer(api.Decomposer) { f.regs-- }

type fakeSubject struct{}

func (fakeSubject) DecomposableType() string { return "fake" }

func TestUnpacker(t *testing.T) {
	t.Parallel()
	inner := &fakeUnpacker{
		lists: []*sbom.NodeList{
			graph([]*sbom.Node{file("a", toolSHA256)}),
			graph([]*sbom.Node{pkg("b", "pkg:generic/other@1")}),
		},
		err: errors.New("partial"),
	}
	u := Wrap(inner, loadTestCatalog(t))

	lists, err := u.Extract(t.Context(), fakeSubject{})
	require.ErrorContains(t, err, "partial", "the inner error is passed through")
	require.Len(t, lists, 2)
	require.Len(t, u.Reports, 2)
	assert.Len(t, u.Reports[0].Stitched, 2)
	assert.Empty(t, u.Reports[1].Stitched)
	assert.Contains(t, edgeSet(lists[0]), "a>tool:generatedFrom")

	u.RegisterDecomposer(nil)
	assert.Equal(t, 1, inner.regs)
	u.UnregisterDecomposer(nil)
	assert.Equal(t, 0, inner.regs)
}

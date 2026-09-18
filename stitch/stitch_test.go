// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pkg(id, purl string, hashes ...string) *sbom.Node {
	n := &sbom.Node{Id: id, Type: sbom.Node_PACKAGE, Name: id}
	if purl != "" {
		n.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): purl}
	}
	if len(hashes) > 0 {
		n.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): hashes[0]}
	}
	if len(hashes) > 1 {
		n.Hashes[int32(sbom.HashAlgorithm_SHA1)] = hashes[1]
	}
	return n
}

func file(id, sha256 string) *sbom.Node {
	return &sbom.Node{
		Id: id, Type: sbom.Node_FILE, Name: id,
		Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): sha256},
	}
}

// graph builds a list from "from>to" dependsOn edges over the given nodes;
// the first node is the root.
func graph(nodes []*sbom.Node, deps ...string) *sbom.NodeList {
	nl := sbom.NewNodeList()
	for i, n := range nodes {
		if i == 0 {
			nl.AddRootNode(n)
		} else {
			nl.AddNode(n)
		}
	}
	for _, d := range deps {
		var from, to string
		for i := range d {
			if d[i] == '>' {
				from, to = d[:i], d[i+1:]
			}
		}
		nl.MergeEdges([]*sbom.Edge{{From: from, Type: sbom.Edge_dependsOn, To: []string{to}}})
	}
	return nl
}

// edgeSet renders the edges as "from>to:type" by node name.
func edgeSet(nl *sbom.NodeList) []string {
	out := make([]string, 0, len(nl.GetEdges()))
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			out = append(out, nl.GetNodeByID(e.GetFrom()).GetName()+">"+nl.GetNodeByID(to).GetName()+":"+e.GetType().String())
		}
	}
	return out
}

func names(nodes []*sbom.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.GetName())
	}
	return out
}

func TestSameComponent(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		a, b *sbom.Node
		want bool
	}{
		"same sha256":                 {pkg("a", "pkg:x/a@1", "h1"), pkg("b", "pkg:x/b@2", "h1"), true},
		"different sha256, same purl": {pkg("a", "pkg:x/a@1", "h1"), pkg("b", "pkg:x/a@1", "h2"), false},
		"no shared algorithm, same purl": {
			pkg("a", "pkg:x/a@1", "h1"),
			&sbom.Node{Id: "b", Type: sbom.Node_PACKAGE, Identifiers: map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): "pkg:x/a@1"}, Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): "s1"}},
			true,
		},
		"sha256 agrees, sha1 disagrees": {pkg("a", "", "h1", "s1"), pkg("b", "", "h1", "s2"), false},
		"no hashes, same purl":          {pkg("a", "pkg:x/a@1"), pkg("b", "pkg:x/a@1"), true},
		"no hashes, different purl":     {pkg("a", "pkg:x/a@1"), pkg("b", "pkg:x/a@2"), false},
		"no hashes, no purl":            {pkg("a", ""), pkg("b", ""), false},
		"file and package, same hash":   {file("f", "h1"), pkg("p", "", "h1"), false},
		"two files, same hash":          {file("f", "h1"), file("g", "h1"), true},
		"two files, different hash":     {file("f", "h1"), file("g", "h2"), false},
		"nil":                           {nil, pkg("a", ""), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, SameComponent(tc.a, tc.b))
			assert.Equal(t, tc.want, SameComponent(tc.b, tc.a), "symmetric")
		})
	}
}

func TestAttach(t *testing.T) {
	t.Parallel()
	dst := graph([]*sbom.Node{file("bin", "h1")})
	src := graph(
		[]*sbom.Node{pkg("app", "pkg:x/app@1"), pkg("lib", "pkg:x/lib@1"), pkg("leaf", "pkg:x/leaf@1"), pkg("stray", "pkg:x/stray@1")},
		"app>lib", "lib>leaf", "leaf>lib", // a cycle below the root
	)
	srcNodes := len(src.GetNodes())

	require.NoError(t, Attach(dst, "bin", src, "app", sbom.Edge_generatedFrom))

	assert.ElementsMatch(t, []string{"bin", "app", "lib", "leaf"}, names(dst.GetNodes()), "the stray is not reachable")
	assert.ElementsMatch(t, []string{
		"bin>app:generatedFrom", "app>lib:dependsOn", "lib>leaf:dependsOn", "leaf>lib:dependsOn",
	}, edgeSet(dst))
	assert.Equal(t, []string{"bin"}, dst.GetRootElements(), "the destination keeps its roots")

	// Copies carry fresh ids and the source is untouched.
	assert.Nil(t, dst.GetNodeByID("app"))
	assert.Len(t, src.GetNodes(), srcNodes)
	assert.NotNil(t, src.GetNodeByID("app"))

	// Attaching the same source again yields a second, independent copy.
	require.NoError(t, Attach(dst, "bin", src, "app", sbom.Edge_generatedFrom))
	assert.Len(t, dst.GetNodes(), 7)

	require.Error(t, Attach(dst, "nope", src, "app", sbom.Edge_contains))
	require.Error(t, Attach(dst, "bin", src, "nope", sbom.Edge_contains))
	require.Error(t, Attach(dst, "bin", nil, "app", sbom.Edge_contains))
}

func TestMerge(t *testing.T) {
	t.Parallel()
	target := pkg("found", "pkg:x/app@1", "h1")
	target.Version = "1"
	target.Licenses = []string{"MIT"}
	dst := graph([]*sbom.Node{target, pkg("mine", "pkg:x/mine@1")}, "found>mine")

	root := pkg("app", "pkg:x/app@1", "h1", "s1")
	root.Version = "9"
	root.Description = "from the supplement"
	root.Licenses = []string{"MIT", "Apache-2.0"}
	root.Properties = []*sbom.Property{{Name: "source", Data: "sbom"}}
	src := graph([]*sbom.Node{root, pkg("lib", "pkg:x/lib@1"), pkg("back", "pkg:x/back@1")}, "app>lib", "lib>back", "back>app")

	require.NoError(t, Merge(dst, "found", src, "app"))

	assert.ElementsMatch(t, []string{"found", "mine", "lib", "back"}, names(dst.GetNodes()), "the root itself is not added")
	assert.ElementsMatch(t, []string{
		"found>mine:dependsOn", "found>lib:dependsOn", "lib>back:dependsOn", "back>found:dependsOn",
	}, edgeSet(dst), "edges leaving or reaching the root now use the target")

	// The target kept its values and gained what it lacked.
	assert.Equal(t, "1", target.GetVersion())
	assert.Equal(t, "from the supplement", target.GetDescription())
	assert.Equal(t, []string{"MIT", "Apache-2.0"}, target.GetLicenses())
	assert.Equal(t, "s1", target.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
	assert.Equal(t, "h1", target.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	assert.Len(t, target.GetProperties(), 1)

	require.Error(t, Merge(dst, "nope", src, "app"))
	require.Error(t, Merge(dst, "found", src, "nope"))
}

func TestDedupe(t *testing.T) {
	t.Parallel()

	t.Run("collapses by hash and purl and rewires", func(t *testing.T) {
		t.Parallel()
		a := pkg("a", "pkg:x/lib@1", "h1")
		a.Licenses = []string{"MIT"}
		a2 := pkg("a2", "pkg:x/lib@1", "h1") // same hash
		a2.Description = "described"
		a3 := pkg("a3", "pkg:x/lib@1")             // no hash, same purl
		other := pkg("other", "pkg:x/lib@1", "h2") // same purl, conflicting hash: stays
		nl := graph(
			[]*sbom.Node{pkg("root", "pkg:x/root@1"), a, a2, a3, other, pkg("dep", "pkg:x/dep@1")},
			"root>a", "root>a2", "root>a3", "root>other", "a2>dep", "a3>dep", "a2>a", // a self loop after the merge
		)
		nl.RootElements = append(nl.RootElements, "a2")

		dropped := Dedupe(nl, nil)

		assert.Equal(t, map[string]string{"a2": "a", "a3": "a"}, dropped)
		assert.ElementsMatch(t, []string{"root", "a", "other", "dep"}, names(nl.GetNodes()))
		assert.ElementsMatch(t, []string{
			"root>a:dependsOn", "root>other:dependsOn", "a>dep:dependsOn",
		}, edgeSet(nl), "duplicate and self edges collapse")
		assert.Equal(t, []string{"root", "a"}, nl.GetRootElements())
		assert.Equal(t, "described", a.GetDescription(), "the survivor absorbs the duplicates")
		assert.Equal(t, []string{"MIT"}, a.GetLicenses())
	})

	t.Run("a hashless node cannot bridge conflicting hashes", func(t *testing.T) {
		t.Parallel()
		// Whatever the order, the two hashed nodes stay apart and the
		// hashless one joins exactly one of them.
		for _, order := range [][]*sbom.Node{
			{pkg("h1", "pkg:x/lib@1", "h1"), pkg("h2", "pkg:x/lib@1", "h2"), pkg("nohash", "pkg:x/lib@1")},
			{pkg("nohash", "pkg:x/lib@1"), pkg("h1", "pkg:x/lib@1", "h1"), pkg("h2", "pkg:x/lib@1", "h2")},
		} {
			nl := graph(order)
			dropped := Dedupe(nl, nil)
			assert.Len(t, dropped, 1)
			require.Len(t, nl.GetNodes(), 2)
			sums := make([]string, 0, 2)
			for _, n := range nl.GetNodes() {
				sums = append(sums, n.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
			}
			assert.ElementsMatch(t, []string{"h1", "h2"}, sums, "each survivor keeps one of the hashes")
		}
	})

	t.Run("nothing to do", func(t *testing.T) {
		t.Parallel()
		nl := graph([]*sbom.Node{pkg("root", "pkg:x/root@1"), pkg("dep", "pkg:x/dep@1")}, "root>dep")
		assert.Empty(t, Dedupe(nl, nil))
		assert.Len(t, nl.GetNodes(), 2)
		assert.Equal(t, []string{"root>dep:dependsOn"}, edgeSet(nl))
	})

	t.Run("files and packages never merge, files with equal hashes do", func(t *testing.T) {
		t.Parallel()
		nl := graph([]*sbom.Node{pkg("p", "", "h1"), file("f", "h1"), file("g", "h1")}, "p>f", "p>g")
		dropped := Dedupe(nl, nil)
		assert.Equal(t, map[string]string{"g": "f"}, dropped)
		assert.Equal(t, []string{"p>f:dependsOn"}, edgeSet(nl))
	})

	t.Run("custom identity", func(t *testing.T) {
		t.Parallel()
		nl := graph([]*sbom.Node{pkg("a", "pkg:x/a@1"), pkg("b", "pkg:x/a@1")})
		byName := func(x, y *sbom.Node) bool { return x.GetName() == y.GetName() }
		assert.Empty(t, Dedupe(nl, byName), "same purl but the identity says no")
		assert.Len(t, nl.GetNodes(), 2)
	})
}

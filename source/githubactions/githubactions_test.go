// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package githubactions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const repoDir = "testdata/repo"

func TestParseWorkflow(t *testing.T) {
	t.Parallel()
	references, err := ReadWorkflow(filepath.Join(repoDir, workflowsDir, "ci.yml"))
	require.NoError(t, err)

	raw := make([]string, 0, len(references))
	for _, reference := range references {
		raw = append(raw, reference.Kind+" "+reference.Raw)
	}
	// What is the repository's own (./), and what is only known when the
	// workflow runs (${{ }}), is left out.
	require.ElementsMatch(t, []string{
		"image node:20-bookworm",
		"image ghcr.io/example/postgres:16@sha256:4c1c4d8a0b6f6d2e0a6b9f6a1f6b2c3d4e5f60718293a4b5c6d7e8f901234567",
		"image redis",
		"action actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"action actions/setup-go@v5",
		"action github/codeql-action/init@v3",
		"image docker://alpine:3.20",
		"reusable-workflow example-org/workflows/.github/workflows/release.yml@main",
	}, raw)

	byRaw := map[string]*Reference{}
	for _, reference := range references {
		byRaw[reference.Raw] = reference
	}

	checkout := byRaw["actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"]
	require.Equal(t, "actions", checkout.Owner)
	require.Equal(t, "checkout", checkout.Repo)
	require.Empty(t, checkout.Path)
	require.True(t, checkout.Pinned())
	require.Equal(t, "v4.1.1", checkout.Comment)
	require.Equal(t, 15, checkout.Line)

	require.False(t, byRaw["actions/setup-go@v5"].Pinned(), "a tag can be moved")
	require.Equal(t, "init", byRaw["github/codeql-action/init@v3"].Path)
	require.Equal(t, ".github/workflows/release.yml",
		byRaw["example-org/workflows/.github/workflows/release.yml@main"].Path)

	postgres := byRaw["ghcr.io/example/postgres:16@sha256:4c1c4d8a0b6f6d2e0a6b9f6a1f6b2c3d4e5f60718293a4b5c6d7e8f901234567"]
	require.Equal(t, "ghcr.io/example/postgres", postgres.Image)
	require.Equal(t, "16", postgres.Tag)
	require.True(t, postgres.Pinned())
	require.Equal(t, "redis", byRaw["redis"].Image)
	require.Empty(t, byRaw["redis"].Tag)
	require.False(t, byRaw["redis"].Pinned())

	// Things that are no workflow, or hold nothing.
	for _, content := range []string{"", "name: empty\n", "jobs: 3\n", "jobs:\n  a:\n    steps: none\n", "- a list\n"} {
		references, err := ParseWorkflow([]byte(content))
		require.NoError(t, err, content)
		require.Empty(t, references, content)
	}
	_, err = ParseWorkflow([]byte("jobs: [unclosed"))
	require.Error(t, err)
}

func TestImageReference(t *testing.T) {
	t.Parallel()
	for raw, expected := range map[string]Reference{
		"node":                           {Image: "node"},
		"node:20":                        {Image: "node", Tag: "20"},
		"library/node:20":                {Image: "library/node", Tag: "20"},
		"ghcr.io/owner/img":              {Image: "ghcr.io/owner/img"},
		"localhost:5000/tools/linter":    {Image: "localhost:5000/tools/linter"},
		"localhost:5000/tools/linter:1":  {Image: "localhost:5000/tools/linter", Tag: "1"},
		"alpine@sha256:abc":              {Image: "alpine", Digest: "sha256:abc"},
		"gcr.io/p/img:1.0@sha256:abcdef": {Image: "gcr.io/p/img", Tag: "1.0", Digest: "sha256:abcdef"},
	} {
		reference := imageReference(raw)
		require.NotNil(t, reference, raw)
		expected.Kind = KindImage
		require.Equal(t, expected, *reference, raw)
	}
	require.Nil(t, imageReference(""))
	require.Nil(t, imageReference("${{ matrix.image }}"))
}

func properties(node *sbom.Node) map[string][]string {
	out := map[string][]string{}
	for _, property := range node.GetProperties() {
		out[property.GetName()] = append(out[property.GetName()], property.GetData())
	}
	return out
}

func TestExtract(t *testing.T) {
	t.Parallel()
	// The inclusion flags are not needed: the decomposer reads nothing
	// but build dependencies.
	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: repoDir, Version: "v1.0.0", CommitHash: "abc"})
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	require.Equal(t, "repo", roots[0].GetName())
	require.Equal(t, "pkg:generic/repo@v1.0.0", string(roots[0].Purl()))

	nodes := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		if node.GetId() != roots[0].GetId() {
			nodes[string(node.Purl())] = node
		}
	}
	related := 0
	for _, edge := range nl.GetEdges() {
		require.Equal(t, roots[0].GetId(), edge.GetFrom())
		require.Equal(t, sbom.Edge_buildDependency, edge.GetType())
		related += len(edge.GetTo())
	}
	require.Equal(t, len(nodes), related)

	// The broken workflow and the README are passed over; the same
	// reference in two workflows is one node, a different ref another.
	purls := make([]string, 0, len(nodes))
	for p := range nodes {
		purls = append(purls, p)
	}
	require.ElementsMatch(t, []string{
		"pkg:github/actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"pkg:github/actions/checkout@v4",
		"pkg:github/actions/setup-go@v5",
		"pkg:github/github/codeql-action@v3#init",
		"pkg:github/example-org/workflows@main#.github/workflows/release.yml",
		"pkg:docker/node@20-bookworm",
		"pkg:docker/redis",
		"pkg:docker/alpine@3.20",
		"pkg:docker/example/postgres@sha256:4c1c4d8a0b6f6d2e0a6b9f6a1f6b2c3d4e5f60718293a4b5c6d7e8f901234567?repository_url=ghcr.io&tag=16",
		"pkg:docker/tools/linter@1.2?repository_url=localhost:5000",
		// Through the repository's own actions.
		"pkg:github/actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9",
		"pkg:docker/example/helper@2?repository_url=ghcr.io",
		"pkg:docker/example/scanner@1.0?repository_url=ghcr.io",
	}, purls)

	checkout := nodes["pkg:github/actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"]
	require.Equal(t, "actions/checkout", checkout.GetName())
	require.Equal(t, "b4ffde65f46336ab88eb53be808477a3936bae11", checkout.GetVersion())
	require.Equal(t, map[string][]string{
		PropertyKind:    {KindAction},
		PropertyPinned:  {"true"},
		PropertyUsedIn:  {".github/workflows/ci.yml:15", ".github/workflows/lint.yaml:10"},
		PropertyComment: {"v4.1.1"},
	}, properties(checkout))
	require.Equal(t, "actions", checkout.GetSuppliers()[0].GetName())
	require.Equal(t, "https://github.com/actions", checkout.GetSuppliers()[0].GetUrl())
	vcs := checkout.GetExternalReferences()[0]
	require.Equal(t, "https://github.com/actions/checkout", vcs.GetUrl())
	require.Equal(t, "b4ffde65f46336ab88eb53be808477a3936bae11", vcs.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])

	tagged := nodes["pkg:github/actions/setup-go@v5"]
	require.Equal(t, []string{"false"}, properties(tagged)[PropertyPinned])
	require.Empty(t, tagged.GetExternalReferences()[0].GetHashes(), "a tag is no commit")

	require.Equal(t, "github/codeql-action/init", nodes["pkg:github/github/codeql-action@v3#init"].GetName())
	require.Equal(t, []string{KindWorkflow},
		properties(nodes["pkg:github/example-org/workflows@main#.github/workflows/release.yml"])[PropertyKind])

	postgres := nodes["pkg:docker/example/postgres@sha256:4c1c4d8a0b6f6d2e0a6b9f6a1f6b2c3d4e5f60718293a4b5c6d7e8f901234567?repository_url=ghcr.io&tag=16"]
	require.Equal(t, "ghcr.io/example/postgres", postgres.GetName())
	require.Equal(t, "4c1c4d8a0b6f6d2e0a6b9f6a1f6b2c3d4e5f60718293a4b5c6d7e8f901234567",
		postgres.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	require.Equal(t, []string{"true"}, properties(postgres)[PropertyPinned])
	require.Empty(t, nodes["pkg:docker/redis"].GetVersion())
}

func TestExtractNoWorkflows(t *testing.T) {
	t.Parallel()
	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.Error(t, err)

	// A workflows directory with nothing to read gives the repository
	// alone.
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o750))
	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: dir})
	require.NoError(t, err)
	require.Len(t, nl.GetNodes(), 1)
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add(filepath.Join("repo", ".github", "workflows"), "ci.yml")
	index.Add(filepath.Join(".github", "workflows"), "release.yaml")
	// No YAML in it, and directories that only look the part.
	index.Add(filepath.Join("empty", ".github", "workflows"), "README.md")
	index.Add(filepath.Join("docs", "workflows"), "ci.yml")
	index.Add(filepath.Join("x", ".github"), "dependabot.yml")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{".", "repo"}, found)
}

func TestParseAction(t *testing.T) {
	t.Parallel()
	read := func(file string) (raw, local []string) {
		data, err := os.ReadFile(filepath.Join(repoDir, file))
		require.NoError(t, err)
		references, local, err := ParseAction(data)
		require.NoError(t, err)
		for _, reference := range references {
			raw = append(raw, reference.Kind+" "+reference.Raw)
		}
		return raw, local
	}

	// A composite action's steps are read like a workflow's.
	raw, local := read(".github/actions/local/action.yml")
	require.Equal(t, []string{"action actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9"}, raw)
	require.Equal(t, []string{"./.github/actions/nested"}, local)

	// A Docker action that pulls its image names it; one built from a
	// Dockerfile names nothing here.
	raw, _ = read("tools/scan/action.yml")
	require.Equal(t, []string{"image docker://ghcr.io/example/scanner:1.0"}, raw)
	raw, local = read("tools/built/action.yml")
	require.Empty(t, raw)
	require.Empty(t, local)

	for _, content := range []string{"", "name: x\n", "runs: 3\n", "runs:\n  using: node20\n  main: index.js\n"} {
		references, local, err := ParseAction([]byte(content))
		require.NoError(t, err, content)
		require.Empty(t, references, content)
		require.Empty(t, local, content)
	}
	_, _, err := ParseAction([]byte("runs: [unclosed"))
	require.Error(t, err)
}

func TestLocalActionPath(t *testing.T) {
	t.Parallel()
	for raw, expected := range map[string]string{
		"./.github/actions/local": ".github/actions/local",
		"./tools/scan/":           "tools/scan",
		"./a/../b":                "b",
		// The repository itself, when it is an action: a common way to
		// test one.
		"./":                ".",
		"./../outside":      "",
		"./a/../../outside": "",
	} {
		require.Equal(t, expected, localActionPath(raw), raw)
	}
}

// TestExtractFollowsLocalActions checks what the repository's own actions
// use is in the graph: through a composite action, the action it uses in
// turn, and a Docker action's image, with two actions that use each
// other read once each.
func TestExtractFollowsLocalActions(t *testing.T) {
	t.Parallel()
	nl, err := New().Extract(&api.DecomposerOptions{WorkDir: repoDir})
	require.NoError(t, err)

	nodes := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		nodes[string(node.Purl())] = node
	}

	cache := nodes["pkg:github/actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9"]
	require.NotNil(t, cache)
	require.Equal(t, []string{".github/actions/local/action.yml:6"}, properties(cache)[PropertyUsedIn])
	require.Equal(t, []string{"v4.0.2"}, properties(cache)[PropertyComment])

	// Used by a workflow and by a local action: one node, both places.
	checkout := nodes["pkg:github/actions/checkout@v4"]
	require.Equal(t, []string{
		".github/workflows/lint.yaml:11", ".github/actions/nested/action.yaml:6",
	}, properties(checkout)[PropertyUsedIn])

	require.Contains(t, nodes, "pkg:docker/example/helper@2?repository_url=ghcr.io")
	scanner := nodes["pkg:docker/example/scanner@1.0?repository_url=ghcr.io"]
	require.NotNil(t, scanner)
	require.Equal(t, []string{"tools/scan/action.yml:5"}, properties(scanner)[PropertyUsedIn])

	// Ten from the workflows, three more through the local actions.
	require.Len(t, nodes, 14)
}

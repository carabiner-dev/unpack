// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const xcodeDir = "testdata/xcode/Demo.xcodeproj/project.xcworkspace/xcshareddata/swiftpm"

func TestParseResolved(t *testing.T) {
	t.Parallel()

	resolved, err := ReadResolved("testdata/v3/Package.resolved")
	require.NoError(t, err)
	require.Equal(t, 3, resolved.Version)
	// Sorted by identity, as SwiftPM writes them.
	identities := make([]string, 0, len(resolved.Pins))
	for _, pin := range resolved.Pins {
		identities = append(identities, pin.Identity)
	}
	require.Equal(t, []string{"internal-kit", "localkit", "mona.linkedlist", "swift-asn1", "swift-nio"}, identities)

	// The first schema names a pin by its repository.
	resolved, err = ReadResolved("testdata/v1/Package.resolved")
	require.NoError(t, err)
	require.Equal(t, 1, resolved.Version)
	require.Equal(t, &Pin{
		Identity: "alamofire", Kind: KindRemote, Location: "https://github.com/Alamofire/Alamofire.git",
		Version: "5.6.2", Revision: "8dd85aee02e39dd280c75eef88ffdb86eed4b07b",
	}, resolved.Pins[0])
	require.Equal(t, "snapkit", resolved.Pins[1].Identity)
	require.Equal(t, "develop", resolved.Pins[1].Branch)
	require.Empty(t, resolved.Pins[1].Version)

	// A schema not yet known is read as the newest known.
	resolved, err = ParseResolved([]byte(`{"version": 4, "pins": [{"identity": "a", "kind": "registry", "state": {"version": "1.0.0"}}]}`))
	require.NoError(t, err)
	require.Equal(t, 4, resolved.Version)
	require.Len(t, resolved.Pins, 1)

	// A project with no dependencies.
	resolved, err = ParseResolved([]byte(`{"pins": [], "version": 2}`))
	require.NoError(t, err)
	require.Empty(t, resolved.Pins)

	for name, data := range map[string]string{
		"not json":        `nope`,
		"no version":      `{"pins": []}`,
		"no identity":     `{"version": 2, "pins": [{"kind": "remoteSourceControl", "state": {"version": "1.0.0"}}]}`,
		"an empty state":  `{"version": 2, "pins": [{"identity": "a", "state": {}}]}`,
		"a state of null": `{"version": 2, "pins": [{"identity": "a", "state": {"version": null, "revision": null}}]}`,
	} {
		_, err := ParseResolved([]byte(data))
		require.ErrorIs(t, err, ErrMalformed, name)
	}
}

func TestIdentityOf(t *testing.T) {
	t.Parallel()
	for location, expected := range map[string]string{
		"https://github.com/Alamofire/Alamofire.git": "alamofire",
		"https://github.com/apple/swift-nio":         "swift-nio",
		"https://github.com/apple/swift-nio/":        "swift-nio",
		"git@github.com:apple/swift-nio.git":         "swift-nio",
		"git@host:Repo.git":                          "repo",
		"/Users/dev/work/LocalKit":                   "localkit",
	} {
		require.Equal(t, expected, IdentityOf(location), location)
	}
}

// TestPURL holds the purls to the ones SwiftPM writes in its own SBOMs.
func TestPURL(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		pin      Pin
		expected string
	}{
		// The example of SE-0509.
		"a version": {
			Pin{Identity: "swift-asn1", Kind: KindRemote, Location: "https://github.com/apple/swift-asn1.git", Version: "1.5.0", Revision: "abc"},
			"pkg:swift/github.com/apple/swift-asn1@1.5.0",
		},
		"an scp location, and a branch: the commit is the version": {
			Pin{Identity: "swift-nio", Kind: KindRemote, Location: "git@github.com:apple/swift-nio.git", Branch: "main", Revision: "f7dc3f527576c398709b017584392fb58592e7f5"},
			"pkg:swift/github.com/apple/swift-nio@f7dc3f527576c398709b017584392fb58592e7f5",
		},
		"a bare commit": {
			Pin{Identity: "kit", Kind: KindRemote, Location: "https://example.com/team/kit", Revision: "0123456789abcdef0123456789abcdef01234567"},
			"pkg:swift/example.com/team/kit@0123456789abcdef0123456789abcdef01234567",
		},
		// Only the host and the first element of the path, as SwiftPM
		// has it.
		"a nested group": {
			Pin{Identity: "internal-kit", Kind: KindRemote, Location: "https://gitlab.example.com/platform/ios/internal-kit", Version: "2.0.0"},
			"pkg:swift/gitlab.example.com/platform/internal-kit@2.0.0",
		},
		"a registry package: scope and name": {
			Pin{Identity: "mona.linkedlist", Kind: KindRegistry, Version: "1.2.0"},
			"pkg:swift/mona/linkedlist@1.2.0",
		},
		// SwiftPM writes the path as it is, where a purl has it
		// percent-encoded; the two read as the same purl.
		"a local repository: no namespace, its path": {
			Pin{Identity: "localkit", Kind: KindLocal, Location: "/Users/dev/work/LocalKit", Version: "0.4.0"},
			"pkg:swift/localkit@0.4.0?path=%2FUsers%2Fdev%2Fwork%2FLocalKit",
		},
		"a location with one element": {
			Pin{Identity: "solo", Kind: KindRemote, Location: "https://example.com/solo.git", Version: "1.0.0"},
			"pkg:swift/solo@1.0.0",
		},
	} {
		require.Equal(t, tc.expected, tc.pin.PURL(), name)
	}
}

func properties(node *sbom.Node) map[string]string {
	out := map[string]string{}
	for _, property := range node.GetProperties() {
		out[property.GetName()] = property.GetData()
	}
	return out
}

func extract(t *testing.T, dir string, opts *api.DecomposerOptions) (root *sbom.Node, nodes map[string]*sbom.Node) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)

	nodes = map[string]*sbom.Node{}
	byID := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
		if node.GetId() != roots[0].GetId() {
			nodes[node.GetName()] = node
		}
	}
	related := 0
	for _, edge := range nl.GetEdges() {
		require.Equal(t, roots[0].GetId(), edge.GetFrom(), "the graph is flat")
		require.Equal(t, sbom.Edge_dependsOn, edge.GetType())
		related += len(edge.GetTo())
	}
	require.Equal(t, len(nodes), related, "every package hangs from the root")
	return roots[0], nodes
}

func TestExtract(t *testing.T) {
	t.Parallel()
	root, nodes := extract(t, "testdata/v3", &api.DecomposerOptions{Version: "v1.2.0", CommitHash: "abc"})
	require.Equal(t, "v3", root.GetName())
	require.Equal(t, "pkg:swift/v3@v1.2.0", string(root.Purl()))
	require.Len(t, root.GetExternalReferences(), 1)
	require.Len(t, nodes, 5)

	// Pinned to a version: the version, with the commit beside it.
	asn1 := nodes["swift-asn1"]
	require.Equal(t, "1.3.0", asn1.GetVersion())
	require.Equal(t, "pkg:swift/github.com/apple/swift-asn1@1.3.0", string(asn1.Purl()))
	require.Equal(t, map[string]string{
		PropertyKind:     KindRemote,
		PropertyRevision: "7faebca1ea4f9aaf0cda1cef7c43aecd2311ddf6",
	}, properties(asn1))
	require.Len(t, asn1.GetExternalReferences(), 1)
	reference := asn1.GetExternalReferences()[0]
	require.Equal(t, sbom.ExternalReference_VCS, reference.GetType())
	require.Equal(t, "https://github.com/apple/swift-asn1.git", reference.GetUrl())
	require.Equal(t, "7faebca1ea4f9aaf0cda1cef7c43aecd2311ddf6", reference.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
	require.Empty(t, asn1.GetHashes(), "a commit is no hash of the package's content")

	// Following a branch: the commit is the version, the branch a
	// property.
	nio := nodes["swift-nio"]
	require.Equal(t, "f7dc3f527576c398709b017584392fb58592e7f5", nio.GetVersion())
	require.Equal(t, "main", properties(nio)[PropertyBranch])

	// A registry package has no repository to point at.
	registry := nodes["mona.linkedlist"]
	require.Equal(t, "pkg:swift/mona/linkedlist@1.2.0", string(registry.Purl()))
	require.Empty(t, registry.GetExternalReferences())
	require.Equal(t, map[string]string{PropertyKind: KindRegistry}, properties(registry))

	require.Equal(t, KindLocal, properties(nodes["localkit"])[PropertyKind])
}

func TestExtractOlderSchemas(t *testing.T) {
	t.Parallel()
	_, nodes := extract(t, "testdata/v1", &api.DecomposerOptions{})
	require.Len(t, nodes, 2)
	require.Equal(t, "pkg:swift/github.com/Alamofire/alamofire@5.6.2", string(nodes["alamofire"].Purl()))
	require.Equal(t, "f222cbdf325885926566172f6f5f06af95473158", nodes["snapkit"].GetVersion())

	// A lockfile Xcode keeps inside a project's bundle is the project's.
	root, nodes := extract(t, xcodeDir, &api.DecomposerOptions{})
	require.Equal(t, "Demo", root.GetName())
	require.Equal(t, "pkg:swift/demo", string(root.Purl()))
	require.Len(t, nodes, 1)
	require.Equal(t, "7.9.1", nodes["kingfisher"].GetVersion())
}

func TestProjectName(t *testing.T) {
	t.Parallel()
	for dir, expected := range map[string]string{
		"/work/MyPackage": "MyPackage",
		"/work/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm":    "App",
		"/work/App.xcworkspace/xcshareddata/swiftpm":                      "App",
		"/work/My App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm": "My App",
		// A directory that only looks the part.
		"/work/notabundle/xcshareddata/swiftpm": "swiftpm",
	} {
		require.Equal(t, expected, projectName(dir), dir)
	}
}

func TestExtractErrors(t *testing.T) {
	t.Parallel()
	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.Error(t, err)
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add("pkg", "Package.swift")
	index.Add("pkg", ResolvedFile)
	index.Add(xcodeDir, ResolvedFile)
	// A package with no lockfile: its dependencies are in a program.
	index.Add("unlocked", "Package.swift")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"pkg", xcodeDir}, found)
}

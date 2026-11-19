// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbt

import (
	"sort"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/maven"
)

func TestCoordinateOf(t *testing.T) {
	t.Parallel()

	for p, expected := range map[string]*maven.Coordinate{
		"pkg:maven/org.scala-lang/scala-library@2.13.14": {
			GroupID: "org.scala-lang", ArtifactID: "scala-library", Version: "2.13.14",
		},
		// sbt's dependency submission writes a classifier as packaging.
		"pkg:maven/org.jline/jline@3.26.3?packaging=jdk8": {
			GroupID: "org.jline", ArtifactID: "jline", Version: "3.26.3", Classifier: "jdk8",
		},
		// The purl specification's own qualifiers.
		"pkg:maven/org.example/lib@1.0?classifier=sources&type=zip": {
			GroupID: "org.example", ArtifactID: "lib", Version: "1.0", Classifier: "sources", Type: "zip",
		},
		// Nothing to ask a Maven repository about.
		"pkg:maven/org.example/unversioned": nil,
		"pkg:maven/nogroup@1.0":             nil,
		"pkg:npm/left-pad@1.3.0":            nil,
		"not a purl":                        nil,
		"":                                  nil,
	} {
		node := &sbom.Node{Identifiers: map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): p}}
		coord, ok := coordinateOf(node)
		if expected == nil {
			require.False(t, ok, p)
			continue
		}
		require.True(t, ok, p)
		require.Equal(t, *expected, coord, p)
	}
}

// TestHashLibraries checks which libraries of a snapshot the repository is
// asked about, and that what it answers reaches their nodes: the build's
// own modules are never asked about, and a library the repository does
// not have is left without a hash.
func TestHashLibraries(t *testing.T) {
	t.Parallel()

	snapshot, err := ReadSnapshot(testSnapshot)
	require.NoError(t, err)
	builder := newSnapshotBuilder(snapshot, "testdata", &api.DecomposerOptions{WorkDir: "testdata"})
	nl, err := builder.build()
	require.NoError(t, err)

	asked := []string{}
	classifiers := map[string]string{}
	builder.hashLibraries(func(coords []maven.Coordinate) map[string]map[string]string {
		answer := map[string]map[string]string{}
		for i := range coords {
			key := coords[i].String()
			asked = append(asked, key)
			classifiers[key] = coords[i].Classifier
			// Everything is published but the stray library, and an
			// algorithm this reader does not record is passed over.
			if coords[i].ArtifactID != "stray" {
				answer[key] = map[string]string{"SHA1": "sha1-of-" + coords[i].ArtifactID, "SHA256": "sha256-of-" + coords[i].ArtifactID, "MD5": "ignored"}
			}
		}
		return answer
	})

	sort.Strings(asked)
	require.Equal(t, []string{
		"org.example:stray:1.0",
		"org.jline:jline:3.26.3",
		"org.scala-lang:scala-library:2.13.14",
		"org.scala-lang:scala3-library_3:3.3.4",
	}, asked)
	require.Equal(t, "jdk8", classifiers["org.jline:jline:3.26.3"])

	jline := nodeByPurl(t, nl, "pkg:maven/org.jline/jline@3.26.3?packaging=jdk8")
	require.Equal(t, map[int32]string{
		int32(sbom.HashAlgorithm_SHA1):   "sha1-of-jline",
		int32(sbom.HashAlgorithm_SHA256): "sha256-of-jline",
	}, jline.GetHashes())
	require.NotEmpty(t, nodeByPurl(t, nl, "pkg:maven/org.scala-lang/scala-library@2.13.14").GetHashes())

	require.Empty(t, nodeByPurl(t, nl, "pkg:maven/org.example/stray@1.0").GetHashes())
	require.Empty(t, nodeByPurl(t, nl, "pkg:maven/com.example/core_3@1.0.0").GetHashes())
	require.Empty(t, nodeByPurl(t, nl, "pkg:maven/com.example/app_3@1.0.0").GetHashes())
}

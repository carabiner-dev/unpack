// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"testing"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestModuleVersion(t *testing.T) {
	t.Parallel()

	const commit = "8060d7a780cd20517729c6e8abeff90b8c426197"
	// Committed in a zone behind UTC: the pseudo-version states UTC.
	committed := time.Date(2026, 11, 17, 11, 29, 5, 0, time.FixedZone("CST", -6*60*60))

	for _, tc := range []struct {
		name     string
		module   string
		opts     api.DecomposerOptions
		expected string
	}{
		{
			name:   "after a release",
			module: "example.com/mod",
			opts: api.DecomposerOptions{
				Version: "v0.3.5-596+8060d7a7", CommitHash: commit, CommitTime: committed,
				AncestorTags: []string{"v0.1.0", "v0.3.5", "v0.3.4"},
			},
			expected: "v0.3.6-0.20261117172905-8060d7a780cd",
		},
		{
			name:   "after a pre-release",
			module: "example.com/mod",
			opts: api.DecomposerOptions{
				CommitHash: commit, CommitTime: committed,
				AncestorTags: []string{"v1.2.2", "v1.2.3-rc.1"},
			},
			expected: "v1.2.3-rc.1.0.20261117172905-8060d7a780cd",
		},
		{
			name:     "with nothing tagged before",
			module:   "example.com/mod",
			opts:     api.DecomposerOptions{CommitHash: commit, CommitTime: committed},
			expected: "v0.0.0-20261117172905-8060d7a780cd",
		},
		{
			name:   "on a tagged commit",
			module: "example.com/mod",
			opts: api.DecomposerOptions{
				Version: "v1.4.0", CommitHash: commit, CommitTime: committed,
				Tags: []string{"latest", "v1.4.0", "v1.4.0-rc.2"}, AncestorTags: []string{"v1.3.0"},
			},
			expected: "v1.4.0",
		},
		{
			// Tags that are not versions of the module say nothing about
			// it: not semantic versions, not canonical ones, and
			// versions of another major than the path's.
			name:   "among tags that are not its versions",
			module: "example.com/mod",
			opts: api.DecomposerOptions{
				CommitHash: commit, CommitTime: committed,
				Tags:         []string{"nightly", "v2.0.0"},
				AncestorTags: []string{"release-9", "v1.5", "1.9.0", "v3.1.0", "v1.1.0", "v1.4.0+meta"},
			},
			expected: "v1.1.1-0.20261117172905-8060d7a780cd",
		},
		{
			name:   "of a major version the path states",
			module: "example.com/mod/v2",
			opts: api.DecomposerOptions{
				CommitHash: commit, CommitTime: committed,
				AncestorTags: []string{"v1.9.0", "v2.0.1", "v3.0.0"},
			},
			expected: "v2.0.2-0.20261117172905-8060d7a780cd",
		},
		{
			name:     "of a major version with nothing tagged in it",
			module:   "example.com/mod/v2",
			opts:     api.DecomposerOptions{CommitHash: commit, CommitTime: committed, AncestorTags: []string{"v1.9.0"}},
			expected: "v2.0.0-20261117172905-8060d7a780cd",
		},
		{
			// No commit time: nothing here describes a commit to name,
			// and the version stated stands, as for a version a caller
			// chose or the one a binary embeds.
			name:     "with a version and no commit time",
			module:   "example.com/mod",
			opts:     api.DecomposerOptions{Version: "v1.9.9", CommitHash: commit, AncestorTags: []string{"v1.0.0"}},
			expected: "v1.9.9",
		},
		{
			name:     "with nothing at all",
			module:   "example.com/mod",
			opts:     api.DecomposerOptions{},
			expected: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			version := moduleVersion(tc.module, &tc.opts)
			require.Equal(t, tc.expected, version)
			if version != "" {
				require.NoError(t, module.Check(tc.module, version), "the go command would refuse this version of the module")
			}
		})
	}
}

// TestRootNodePseudoVersion checks the version reaches the root node and
// its purl.
func TestRootNodePseudoVersion(t *testing.T) {
	t.Parallel()

	d := Decomposer{}
	nl, err := d.BuildNodeList(
		&ModuleSet{Main: Module{Path: "example.com/app"}},
		&api.DecomposerOptions{
			Version:      "v1.2.3-4+8060d7a7",
			CommitHash:   "8060d7a780cd20517729c6e8abeff90b8c426197",
			CommitTime:   time.Date(2026, 11, 17, 17, 29, 5, 0, time.UTC),
			AncestorTags: []string{"v1.2.3"},
			Networking:   api.NetworkDisabled,
		},
	)
	require.NoError(t, err)

	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.Equal(t, "v1.2.4-0.20261117172905-8060d7a780cd", root.GetVersion())
	require.Equal(t, "pkg:golang/example.com/app@v1.2.4-0.20261117172905-8060d7a780cd",
		root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
	require.True(t, module.IsPseudoVersion(root.GetVersion()))
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseReference(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		expect  *Reference
		mustErr bool
	}{
		// Shorthand form
		{
			"shorthand-github", "github:org/repo@v1.0.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "v1.0.0"}, false,
		},
		{
			"shorthand-latest", "github:org/repo",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo"}, false,
		},
		{
			"shorthand-enterprise-host", "github:ghe.example.com/org/repo@v2.0.0",
			&Reference{Forge: "github", Host: "ghe.example.com", Repo: "org/repo", Tag: "v2.0.0"}, false,
		},
		{
			"shorthand-explicit-default-host", "github:github.com/org/repo@v1.0.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "v1.0.0"}, false,
		},
		{
			"shorthand-gitlab-nested", "gitlab:group/subgroup/project@v1.0.0",
			&Reference{Forge: "gitlab", Host: "gitlab.com", Repo: "group/subgroup/project", Tag: "v1.0.0"}, false,
		},
		{
			"shorthand-gitlab-dotted-namespace", "gitlab:some.user/project@v1.0.0",
			&Reference{Forge: "gitlab", Host: "gitlab.com", Repo: "some.user/project", Tag: "v1.0.0"}, false,
		},
		{
			"shorthand-tag-with-at", "github:org/repo@pkg@v1.0.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "pkg@v1.0.0"}, false,
		},
		{
			"shorthand-tag-with-slash", "github:org/repo@components/v1.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "components/v1.0"}, false,
		},

		// Canonical form
		{
			"canonical-github", "github+https://github.com/org/repo@v1.0.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "v1.0.0"}, false,
		},
		{
			"canonical-gitlab-custom-host", "gitlab+https://gitlab.example.com/group/sub/project@v1.0.0",
			&Reference{Forge: "gitlab", Host: "gitlab.example.com", Repo: "group/sub/project", Tag: "v1.0.0"}, false,
		},
		{
			"canonical-unknown-forge", "forgejo+https://codeberg.org/org/repo@v1.0.0",
			&Reference{Forge: "forgejo", Host: "codeberg.org", Repo: "org/repo", Tag: "v1.0.0"}, false,
		},
		{
			"canonical-latest", "github+https://github.com/org/repo",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo"}, false,
		},

		// Pasted URLs
		{
			"url-github-release", "https://github.com/org/repo/releases/tag/v1.0.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "v1.0.0"}, false,
		},
		{
			"url-github-escaped-tag", "https://github.com/org/repo/releases/tag/components%2Fv1.0",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "components/v1.0"}, false,
		},
		{
			"url-github-repo", "https://github.com/org/repo",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo"}, false,
		},
		{
			"url-github-latest", "https://github.com/org/repo/releases/latest",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo"}, false,
		},
		{
			"url-github-releases-index", "https://github.com/org/repo/releases",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo"}, false,
		},
		{
			"url-gitlab-release", "https://gitlab.com/group/sub/project/-/releases/v1.0.0",
			&Reference{Forge: "gitlab", Host: "gitlab.com", Repo: "group/sub/project", Tag: "v1.0.0"}, false,
		},
		{
			"url-gitlab-releases-index", "https://gitlab.com/group/project/-/releases",
			&Reference{Forge: "gitlab", Host: "gitlab.com", Repo: "group/project"}, false,
		},
		{
			"url-gitlab-latest-permalink", "https://gitlab.com/group/project/-/releases/permalink/latest",
			&Reference{Forge: "gitlab", Host: "gitlab.com", Repo: "group/project"}, false,
		},
		{
			"url-gitlab-repo", "https://gitlab.com/group/project",
			&Reference{Forge: "gitlab", Host: "gitlab.com", Repo: "group/project"}, false,
		},

		// Errors
		{"empty", "", nil, true},
		{"blank", "   ", nil, true},
		{"insecure-url", "http://github.com/org/repo", nil, true},
		{"url-unknown-host", "https://codeberg.org/org/repo", nil, true},
		{"no-forge-prefix", "org/repo@v1.0.0", nil, true},
		{"empty-forge", ":org/repo", nil, true},
		{"empty-locator", "github:", nil, true},
		{"empty-tag", "github:org/repo@", nil, true},
		{"single-segment-repo", "github:justarepo", nil, true},
		{"github-nested-repo", "github:org/repo/extra", nil, true},
		{"empty-repo-segment", "github:org//repo", nil, true},
		{"unknown-forge-no-host", "forgejo:org/repo", nil, true},
		{"canonical-no-repo", "github+https://github.com", nil, true},
		{"canonical-empty-forge", "+https://github.com/org/repo", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref, err := ParseReference(tc.input)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, ref)
		})
	}
}

func TestReferenceString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		ref    *Reference
		expect string
	}{
		{
			"with-tag",
			&Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "v1.0.0"},
			"github+https://github.com/org/repo@v1.0.0",
		},
		{
			"latest",
			&Reference{Forge: "gitlab", Host: "gitlab.example.com", Repo: "group/sub/project"},
			"gitlab+https://gitlab.example.com/group/sub/project",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expect, tc.ref.String())

			// The canonical string form must parse back to the same reference.
			parsed, err := ParseReference(tc.ref.String())
			require.NoError(t, err)
			require.Equal(t, tc.ref, parsed)
		})
	}
}

func TestReferenceRepoURL(t *testing.T) {
	t.Parallel()
	ref := &Reference{Forge: "github", Host: "github.com", Repo: "org/repo", Tag: "v1.0.0"}
	require.Equal(t, "https://github.com/org/repo", ref.RepoURL())
}

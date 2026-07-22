// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/carabiner-dev/github"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// API paths and commit digests matching the fixtures in testdata/github.
const (
	ghTestRepoPath      = "repos/carabiner-dev/demo"
	ghTestRelV1Path     = "repos/carabiner-dev/demo/releases/tags/v1.0.0"
	ghTestRelLatestPath = "repos/carabiner-dev/demo/releases/latest"
	ghTestRefV1Path     = "repos/carabiner-dev/demo/git/ref/tags/v1.0.0"
	ghTestRefV2Path     = "repos/carabiner-dev/demo/git/ref/tags/v2.0.0"
	ghTestTagObjPath    = "repos/carabiner-dev/demo/git/tags/ad83c0e21b0f4f7d9f6f0d1a2b3c4d5e6f708192"

	ghTestCommitV1 = "1f2e3d4c5b6a79880912233445566778899aabbc"
	ghTestCommitV2 = "c0ffee0123456789abcdef0123456789abcdef01"
)

// ghRouteCaller is a github.Caller test double that routes API paths to
// fixture files under testdata/github, recording every request it serves.
// Paths in notFound are answered as the native caller surfaces a 404: a
// response carrying the status code plus an error. Paths in failures fail
// with no response, like a transport error.
type ghRouteCaller struct {
	fixtures map[string]string
	notFound map[string]bool
	failures map[string]error
	calls    []string
}

func (c *ghRouteCaller) RequestWithContext(_ context.Context, method, path string, _ io.Reader) (*http.Response, error) {
	c.calls = append(c.calls, path)
	if method != http.MethodGet {
		return nil, fmt.Errorf("unexpected method %q requesting %q", method, path)
	}
	if err, ok := c.failures[path]; ok {
		return nil, err
	}
	if c.notFound[path] {
		body := `{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}`
		return &http.Response{
			Status:     "404 Not Found",
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, fmt.Errorf("HTTP Error %d sending request: %s", http.StatusNotFound, "Not Found")
	}
	fixture, ok := c.fixtures[path]
	if !ok {
		return nil, fmt.Errorf("no fixture routed for path %q", path)
	}
	f, err := os.Open(filepath.Join("testdata", "github", fixture))
	if err != nil {
		return nil, fmt.Errorf("opening fixture: %w", err)
	}
	return &http.Response{
		Status:     "OK",
		StatusCode: http.StatusOK,
		Body:       f,
	}, nil
}

// ghTestRef returns a reference to the fixture repository release cut from
// tag, or to its latest release when tag is empty.
func ghTestRef(tag string) *Reference {
	return &Reference{Forge: ForgeGitHub, Host: "github.com", Repo: "carabiner-dev/demo", Tag: tag}
}

// ghV1Fixtures returns the routes serving the v1.0.0 release fixtures with
// its annotated tag chain, reading the repository from repoFixture.
func ghV1Fixtures(repoFixture string) map[string]string {
	return map[string]string{
		ghTestRelV1Path:  "release-v1.json",
		ghTestRefV1Path:  "tag-ref-v1-annotated.json",
		ghTestTagObjPath: "tag-object-v1.json",
		ghTestRepoPath:   repoFixture,
	}
}

func TestGitHubFetchReleaseMetadata(t *testing.T) {
	t.Parallel()

	publishedV1 := time.Date(2026, time.March, 2, 12, 30, 45, 0, time.UTC)
	publishedV2 := time.Date(2026, time.June, 15, 8, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name         string
		ref          *Reference
		fixtures     map[string]string
		notFound     map[string]bool
		failures     map[string]error
		mustErr      bool
		errContains  string
		expect       *Metadata
		expectAssets int
		expectCalls  int
	}{
		{
			name:     "tagged release with annotated tag chain",
			ref:      ghTestRef("v1.0.0"),
			fixtures: ghV1Fixtures("repo-licensed.json"),
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://github.com/carabiner-dev/demo/releases/tag/v1.0.0",
				Commit:    ghTestCommitV1,
				License:   "Apache-2.0",
				RepoURL:   "https://github.com/carabiner-dev/demo",
				Published: &publishedV1,
			},
			expectAssets: 4,
			expectCalls:  4,
		},
		{
			name: "latest release with lightweight tag",
			ref:  ghTestRef(""),
			fixtures: map[string]string{
				ghTestRelLatestPath: "release-latest.json",
				ghTestRefV2Path:     "tag-ref-v2-lightweight.json",
				ghTestRepoPath:      "repo-licensed.json",
			},
			expect: &Metadata{
				Name:      "v2.0.0",
				Tag:       "v2.0.0",
				URL:       "https://github.com/carabiner-dev/demo/releases/tag/v2.0.0",
				Commit:    ghTestCommitV2,
				License:   "Apache-2.0",
				RepoURL:   "https://github.com/carabiner-dev/demo",
				Published: &publishedV2,
			},
			expectAssets: 1,
			expectCalls:  3,
		},
		{
			name:     "repository without license",
			ref:      ghTestRef("v1.0.0"),
			fixtures: ghV1Fixtures("repo-unlicensed.json"),
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://github.com/carabiner-dev/demo/releases/tag/v1.0.0",
				Commit:    ghTestCommitV1,
				License:   "",
				RepoURL:   "https://github.com/carabiner-dev/demo",
				Published: &publishedV1,
			},
			expectAssets: 4,
			expectCalls:  4,
		},
		{
			name:     "license without spdx mapping",
			ref:      ghTestRef("v1.0.0"),
			fixtures: ghV1Fixtures("repo-noassertion.json"),
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://github.com/carabiner-dev/demo/releases/tag/v1.0.0",
				Commit:    ghTestCommitV1,
				License:   "",
				RepoURL:   "https://github.com/carabiner-dev/demo",
				Published: &publishedV1,
			},
			expectAssets: 4,
			expectCalls:  4,
		},
		{
			name: "deleted tag leaves the commit empty",
			ref:  ghTestRef("v1.0.0"),
			fixtures: map[string]string{
				ghTestRelV1Path: "release-v1.json",
				ghTestRepoPath:  "repo-licensed.json",
			},
			notFound: map[string]bool{ghTestRefV1Path: true},
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://github.com/carabiner-dev/demo/releases/tag/v1.0.0",
				Commit:    "",
				License:   "Apache-2.0",
				RepoURL:   "https://github.com/carabiner-dev/demo",
				Published: &publishedV1,
			},
			expectAssets: 4,
			expectCalls:  3,
		},
		{
			name:        "release not found",
			ref:         ghTestRef("v1.0.0"),
			notFound:    map[string]bool{ghTestRelV1Path: true},
			mustErr:     true,
			errContains: "HTTP Error 404",
		},
		{
			name: "tag reference failure other than 404 is fatal",
			ref:  ghTestRef("v1.0.0"),
			fixtures: map[string]string{
				ghTestRelV1Path: "release-v1.json",
			},
			failures:    map[string]error{ghTestRefV1Path: errors.New("api meltdown")},
			mustErr:     true,
			errContains: "api meltdown",
		},
		{
			name:        "repository fetch failure",
			ref:         ghTestRef("v1.0.0"),
			fixtures:    ghV1Fixtures("repo-licensed.json"),
			failures:    map[string]error{ghTestRepoPath: errors.New("boom")},
			mustErr:     true,
			errContains: "boom",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			caller := &ghRouteCaller{fixtures: tc.fixtures, notFound: tc.notFound, failures: tc.failures}
			backend := &GitHubBackend{caller: caller}

			md, err := backend.FetchReleaseMetadata(t.Context(), tc.ref)
			if tc.mustErr {
				require.Error(t, err)
				if tc.errContains != "" {
					require.ErrorContains(t, err, tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, md)

			assert.Equal(t, tc.expect.Name, md.Name)
			assert.Equal(t, tc.expect.Tag, md.Tag)
			assert.Equal(t, tc.expect.URL, md.URL)
			assert.Equal(t, tc.expect.Commit, md.Commit)
			assert.Equal(t, tc.expect.License, md.License)
			assert.Equal(t, tc.expect.RepoURL, md.RepoURL)
			require.NotNil(t, md.Published)
			assert.True(t, tc.expect.Published.Equal(*md.Published), "unexpected publication time")

			assets, ok := md.BackendData.([]ghAsset)
			require.True(t, ok, "metadata must stash the release assets")
			assert.Len(t, assets, tc.expectAssets)
			assert.Len(t, caller.calls, tc.expectCalls)
		})
	}
}

func TestGitHubFetchArtifactData(t *testing.T) {
	t.Parallel()

	t.Run("reuses stashed assets", func(t *testing.T) {
		t.Parallel()
		caller := &ghRouteCaller{fixtures: ghV1Fixtures("repo-licensed.json")}
		backend := &GitHubBackend{caller: caller}

		md, err := backend.FetchReleaseMetadata(t.Context(), ghTestRef("v1.0.0"))
		require.NoError(t, err)
		callsBefore := len(caller.calls)

		artifacts, err := backend.FetchArtifactData(t.Context(), ghTestRef("v1.0.0"), md)
		require.NoError(t, err)
		assert.Len(t, caller.calls, callsBefore, "stashed assets must not trigger new API calls")
		require.Len(t, artifacts, 4)

		linux := artifacts[0]
		assert.Equal(t, "demo_v1.0.0_linux_amd64.tar.gz", linux.Name)
		assert.Equal(
			t,
			"https://github.com/carabiner-dev/demo/releases/download/v1.0.0/demo_v1.0.0_linux_amd64.tar.gz",
			linux.DownloadURL,
		)
		assert.Equal(t, int64(4194304), linux.Size)
		assert.Equal(t, "application/gzip", linux.ContentType)
		assert.Equal(
			t,
			"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			linux.Digests[sbom.HashAlgorithm_SHA256],
		)

		assert.Empty(t, artifacts[2].Digests, "null digests must be skipped")
		assert.Empty(t, artifacts[3].Digests, "non sha256 digests must be skipped")
	})

	t.Run("refetches pinned to the metadata tag", func(t *testing.T) {
		t.Parallel()
		caller := &ghRouteCaller{fixtures: map[string]string{ghTestRelV1Path: "release-v1.json"}}
		backend := &GitHubBackend{caller: caller}

		// The latest (untagged) reference must be refetched by the tag pinned
		// in the metadata, not through the moving latest endpoint.
		artifacts, err := backend.FetchArtifactData(t.Context(), ghTestRef(""), &Metadata{Tag: "v1.0.0"})
		require.NoError(t, err)
		assert.Equal(t, []string{ghTestRelV1Path}, caller.calls)
		assert.Len(t, artifacts, 4)
	})

	t.Run("refetches the latest release when no tag is known", func(t *testing.T) {
		t.Parallel()
		caller := &ghRouteCaller{fixtures: map[string]string{ghTestRelLatestPath: "release-latest.json"}}
		backend := &GitHubBackend{caller: caller}

		artifacts, err := backend.FetchArtifactData(
			t.Context(), ghTestRef(""), &Metadata{BackendData: "not the assets"},
		)
		require.NoError(t, err)
		assert.Equal(t, []string{ghTestRelLatestPath}, caller.calls)
		assert.Len(t, artifacts, 1)
	})

	t.Run("propagates refetch errors", func(t *testing.T) {
		t.Parallel()
		caller := &ghRouteCaller{failures: map[string]error{ghTestRelV1Path: errors.New("kaboom")}}
		backend := &GitHubBackend{caller: caller}

		_, err := backend.FetchArtifactData(t.Context(), ghTestRef("v1.0.0"), &Metadata{Tag: "v1.0.0"})
		require.ErrorContains(t, err, "kaboom")
	})
}

func TestGitHubAPIClientHost(t *testing.T) {
	t.Parallel()
	backend := NewGitHubBackend()
	for _, tc := range []struct {
		name   string
		host   string
		expect string
	}{
		{"public instance", "github.com", github.DefaultAPIHostname},
		{"enterprise instance", "ghe.example.com", "ghe.example.com/api/v3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, err := backend.apiClient(&Reference{Forge: ForgeGitHub, Host: tc.host, Repo: "org/repo"})
			require.NoError(t, err)
			assert.Equal(t, tc.expect, client.Options.Host)
		})
	}
}

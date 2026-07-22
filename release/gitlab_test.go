// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// API paths (as escaped by the backend) matching the fixtures in
// testdata/gitlab.
const (
	glTestProjectPath   = "projects/carabiner-dev%2Fdemo"
	glTestRelV1Path     = "projects/carabiner-dev%2Fdemo/releases/v1.0.0"
	glTestRelLatestPath = "projects/carabiner-dev%2Fdemo/releases/permalink/latest"

	glTestCommitV1 = "9d1c3e0f2a4b5c6d7e8f90a1b2c3d4e5f6a7b8c9"
	glTestCommitV2 = "b4dc0de5566778899aabbccddeeff00112233445"
)

// glRouteTripper is an http.RoundTripper test double routing GitLab API paths
// to fixture files under testdata/gitlab, recording every request it serves.
// Paths in statuses are answered with that HTTP status and a GitLab-style
// error body; paths in failures fail like a transport error.
type glRouteTripper struct {
	host     string
	fixtures map[string]string
	statuses map[string]int
	failures map[string]error
	requests []*http.Request
}

func (rt *glRouteTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.requests = append(rt.requests, req)
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("unexpected scheme %q in request to %q", req.URL.Scheme, req.URL)
	}
	if req.URL.Host != rt.host {
		return nil, fmt.Errorf("unexpected host %q in request to %q", req.URL.Host, req.URL)
	}
	path, ok := strings.CutPrefix(req.URL.EscapedPath(), "/api/v4/")
	if !ok {
		return nil, fmt.Errorf("request path %q is not under /api/v4/", req.URL.EscapedPath())
	}
	if err, isFailure := rt.failures[path]; isFailure {
		return nil, err
	}
	if status, hasStatus := rt.statuses[path]; hasStatus {
		return &http.Response{
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(`{"message":"404 Project Not Found"}`)),
		}, nil
	}
	fixture, ok := rt.fixtures[path]
	if !ok {
		return nil, fmt.Errorf("no fixture routed for path %q", path)
	}
	f, err := os.Open(filepath.Join("testdata", "gitlab", fixture))
	if err != nil {
		return nil, fmt.Errorf("opening fixture: %w", err)
	}
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Body:       f,
	}, nil
}

// paths returns the escaped API paths of the recorded requests, with the
// query string appended when one was sent.
func (rt *glRouteTripper) paths() []string {
	paths := make([]string, 0, len(rt.requests))
	for _, req := range rt.requests {
		path := strings.TrimPrefix(req.URL.EscapedPath(), "/api/v4/")
		if req.URL.RawQuery != "" {
			path += "?" + req.URL.RawQuery
		}
		paths = append(paths, path)
	}
	return paths
}

// glTestRef returns a reference to the fixture project release cut from tag,
// or to its latest release when tag is empty.
func glTestRef(tag string) *Reference {
	return &Reference{Forge: ForgeGitLab, Host: "gitlab.com", Repo: "carabiner-dev/demo", Tag: tag}
}

// glV1Fixtures returns the routes serving the v1.0.0 release fixtures,
// reading the project from projectFixture.
func glV1Fixtures(projectFixture string) map[string]string {
	return map[string]string{
		glTestRelV1Path:   "release-v1.json",
		glTestProjectPath: projectFixture,
	}
}

func TestGitLabFetchReleaseMetadata(t *testing.T) {
	t.Parallel()

	releasedV1 := time.Date(2026, time.March, 2, 12, 30, 45, 0, time.UTC)
	releasedV2 := time.Date(2026, time.June, 15, 8, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name        string
		ref         *Reference
		fixtures    map[string]string
		statuses    map[string]int
		failures    map[string]error
		mustErr     bool
		errContains string
		expect      *Metadata
		expectLinks int
		expectPaths []string
	}{
		{
			name:     "tagged release",
			ref:      glTestRef("v1.0.0"),
			fixtures: glV1Fixtures("project-licensed.json"),
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://gitlab.com/carabiner-dev/demo/-/releases/v1.0.0",
				Commit:    glTestCommitV1,
				License:   "apache-2.0",
				RepoURL:   "https://gitlab.com/carabiner-dev/demo",
				Published: &releasedV1,
			},
			expectLinks: 2,
			expectPaths: []string{glTestRelV1Path, glTestProjectPath + "?license=true"},
		},
		{
			name: "latest release with unnamed release",
			ref:  glTestRef(""),
			fixtures: map[string]string{
				glTestRelLatestPath: "release-latest.json",
				glTestProjectPath:   "project-licensed.json",
			},
			expect: &Metadata{
				Name:      "v2.0.0",
				Tag:       "v2.0.0",
				URL:       "https://gitlab.com/carabiner-dev/demo/-/releases/v2.0.0",
				Commit:    glTestCommitV2,
				License:   "apache-2.0",
				RepoURL:   "https://gitlab.com/carabiner-dev/demo",
				Published: &releasedV2,
			},
			expectLinks: 1,
			expectPaths: []string{glTestRelLatestPath, glTestProjectPath + "?license=true"},
		},
		{
			name:     "project without license",
			ref:      glTestRef("v1.0.0"),
			fixtures: glV1Fixtures("project-unlicensed.json"),
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://gitlab.com/carabiner-dev/demo/-/releases/v1.0.0",
				Commit:    glTestCommitV1,
				License:   "",
				RepoURL:   "https://gitlab.com/carabiner-dev/demo",
				Published: &releasedV1,
			},
			expectLinks: 2,
			expectPaths: []string{glTestRelV1Path, glTestProjectPath + "?license=true"},
		},
		{
			name: "nested group and slashed tag are escaped",
			ref: &Reference{
				Forge: ForgeGitLab, Host: "gitlab.com", Repo: "group/sub/demo", Tag: "components/v1.0",
			},
			fixtures: map[string]string{
				"projects/group%2Fsub%2Fdemo/releases/components%2Fv1.0": "release-v1.json",
				"projects/group%2Fsub%2Fdemo":                            "project-licensed.json",
			},
			expect: &Metadata{
				Name:      "Demo v1.0.0",
				Tag:       "v1.0.0",
				URL:       "https://gitlab.com/carabiner-dev/demo/-/releases/v1.0.0",
				Commit:    glTestCommitV1,
				License:   "apache-2.0",
				RepoURL:   "https://gitlab.com/group/sub/demo",
				Published: &releasedV1,
			},
			expectLinks: 2,
			expectPaths: []string{
				"projects/group%2Fsub%2Fdemo/releases/components%2Fv1.0",
				"projects/group%2Fsub%2Fdemo?license=true",
			},
		},
		{
			name:        "release not found",
			ref:         glTestRef("v1.0.0"),
			statuses:    map[string]int{glTestRelV1Path: http.StatusNotFound},
			mustErr:     true,
			errContains: "404 Project Not Found",
		},
		{
			name:        "project fetch failure",
			ref:         glTestRef("v1.0.0"),
			fixtures:    glV1Fixtures("project-licensed.json"),
			failures:    map[string]error{glTestProjectPath: errors.New("api meltdown")},
			mustErr:     true,
			errContains: "api meltdown",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tripper := &glRouteTripper{
				host: tc.ref.Host, fixtures: tc.fixtures, statuses: tc.statuses, failures: tc.failures,
			}
			backend := &GitLabBackend{transport: tripper}

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

			links, ok := md.BackendData.([]glAssetLink)
			require.True(t, ok, "metadata must stash the release asset links")
			assert.Len(t, links, tc.expectLinks)
			assert.Equal(t, tc.expectPaths, tripper.paths())
		})
	}
}

func TestGitLabFetchArtifactData(t *testing.T) {
	t.Parallel()

	t.Run("reuses stashed links ignoring source archives", func(t *testing.T) {
		t.Parallel()
		tripper := &glRouteTripper{host: "gitlab.com", fixtures: glV1Fixtures("project-licensed.json")}
		backend := &GitLabBackend{transport: tripper}

		md, err := backend.FetchReleaseMetadata(t.Context(), glTestRef("v1.0.0"))
		require.NoError(t, err)
		callsBefore := len(tripper.requests)

		artifacts, err := backend.FetchArtifactData(t.Context(), glTestRef("v1.0.0"), md)
		require.NoError(t, err)
		assert.Len(t, tripper.requests, callsBefore, "stashed links must not trigger new API calls")

		// The two asset links map to artifacts; the source archives do not.
		require.Len(t, artifacts, 2)
		assert.Equal(t, "demo_v1.0.0_linux_amd64.tar.gz", artifacts[0].Name)
		assert.Equal(
			t,
			"https://gitlab.com/carabiner-dev/demo/-/releases/v1.0.0/downloads/demo_v1.0.0_linux_amd64.tar.gz",
			artifacts[0].DownloadURL,
			"the direct asset URL must win over the raw link URL",
		)
		assert.Empty(t, artifacts[0].Digests, "gitlab reports no asset digests")

		assert.Equal(t, "external-mirror.tar.gz", artifacts[1].Name)
		assert.Equal(
			t,
			"https://downloads.example.com/demo/v1.0.0/demo.tar.gz",
			artifacts[1].DownloadURL,
			"links without a direct asset URL fall back to the raw URL",
		)
	})

	t.Run("refetches pinned to the metadata tag", func(t *testing.T) {
		t.Parallel()
		tripper := &glRouteTripper{
			host: "gitlab.com", fixtures: map[string]string{glTestRelV1Path: "release-v1.json"},
		}
		backend := &GitLabBackend{transport: tripper}

		// The latest (untagged) reference must be refetched by the tag pinned
		// in the metadata, not through the moving latest endpoint.
		artifacts, err := backend.FetchArtifactData(t.Context(), glTestRef(""), &Metadata{Tag: "v1.0.0"})
		require.NoError(t, err)
		assert.Equal(t, []string{glTestRelV1Path}, tripper.paths())
		assert.Len(t, artifacts, 2)
	})

	t.Run("refetches the latest release when no tag is known", func(t *testing.T) {
		t.Parallel()
		tripper := &glRouteTripper{
			host: "gitlab.com", fixtures: map[string]string{glTestRelLatestPath: "release-latest.json"},
		}
		backend := &GitLabBackend{transport: tripper}

		artifacts, err := backend.FetchArtifactData(
			t.Context(), glTestRef(""), &Metadata{BackendData: "not the links"},
		)
		require.NoError(t, err)
		assert.Equal(t, []string{glTestRelLatestPath}, tripper.paths())
		assert.Len(t, artifacts, 1)
	})

	t.Run("propagates refetch errors", func(t *testing.T) {
		t.Parallel()
		tripper := &glRouteTripper{
			host: "gitlab.com", failures: map[string]error{glTestRelV1Path: errors.New("kaboom")},
		}
		backend := &GitLabBackend{transport: tripper}

		_, err := backend.FetchArtifactData(t.Context(), glTestRef("v1.0.0"), &Metadata{Tag: "v1.0.0"})
		require.ErrorContains(t, err, "kaboom")
	})
}

func TestGitLabTokenHeader(t *testing.T) {
	// This test manipulates the environment, so neither it nor its subtests
	// can run in parallel.
	t.Run("token sent when set", func(t *testing.T) {
		t.Setenv(glTokenVar, "sekrit")
		tripper := &glRouteTripper{host: "gitlab.com", fixtures: glV1Fixtures("project-licensed.json")}
		backend := &GitLabBackend{transport: tripper}

		_, err := backend.FetchReleaseMetadata(t.Context(), glTestRef("v1.0.0"))
		require.NoError(t, err)
		require.NotEmpty(t, tripper.requests)
		for _, req := range tripper.requests {
			assert.Equal(t, "sekrit", req.Header.Get("Private-Token"))
		}
	})

	t.Run("anonymous when unset", func(t *testing.T) {
		t.Setenv(glTokenVar, "")
		tripper := &glRouteTripper{host: "gitlab.com", fixtures: glV1Fixtures("project-licensed.json")}
		backend := &GitLabBackend{transport: tripper}

		_, err := backend.FetchReleaseMetadata(t.Context(), glTestRef("v1.0.0"))
		require.NoError(t, err)
		require.NotEmpty(t, tripper.requests)
		for _, req := range tripper.requests {
			assert.Empty(t, req.Header.Values("Private-Token"))
		}
	})
}

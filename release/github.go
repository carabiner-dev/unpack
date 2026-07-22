// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/carabiner-dev/github"
	"github.com/protobom/protobom/pkg/sbom"
)

const (
	// githubPublicHost is the host of the public GitHub instance, served by
	// the API at github.DefaultAPIHostname. Any other host is assumed to be a
	// GitHub Enterprise instance exposing the API under /api/v3.
	githubPublicHost = "github.com"

	// ghObjectTypeTag is the git object type of annotated tags, which need to
	// be dereferenced to get to the commit they point to.
	ghObjectTypeTag = "tag"

	// maxTagDereferences bounds the annotated tag chain walked when resolving
	// the release commit.
	maxTagDereferences = 5

	// spdxNoAssertion is the identifier GitHub reports for licenses it cannot
	// map to an SPDX license, treated as no license data.
	spdxNoAssertion = "NOASSERTION"
)

// errGitHubNotFound marks errors caused by the GitHub API returning a 404 for
// the requested object.
var errGitHubNotFound = errors.New("object not found in the github API")

// GitHubBackend implements the release Backend on top of the GitHub REST API.
// It works against the public github.com instance and against GitHub
// Enterprise hosts, authenticating with the GITHUB_TOKEN environment variable
// when it is set.
type GitHubBackend struct {
	caller github.Caller
}

// NewGitHubBackend creates a new GitHub release backend.
func NewGitHubBackend() *GitHubBackend {
	return &GitHubBackend{}
}

var _ Backend = (*GitHubBackend)(nil)

// ghRelease models the release object returned by the GitHub releases API.
type ghRelease struct {
	TagName     string     `json:"tag_name"`
	Name        string     `json:"name"`
	HTMLURL     string     `json:"html_url"`
	PublishedAt *time.Time `json:"published_at"`
	Assets      []ghAsset  `json:"assets"`
}

// ghAsset models an artifact published in a GitHub release.
type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	ContentType        string `json:"content_type"`
	Digest             string `json:"digest"`
}

// ghRepository models the repository fields the backend reads.
type ghRepository struct {
	License *ghLicense `json:"license"`
}

// ghLicense models the license block of a GitHub repository.
type ghLicense struct {
	SPDXID string `json:"spdx_id"`
}

// ghGitRef models a git reference as returned by the git database API.
type ghGitRef struct {
	Ref    string      `json:"ref"`
	Object ghGitObject `json:"object"`
}

// ghGitTag models an annotated tag object from the git database API.
type ghGitTag struct {
	SHA    string      `json:"sha"`
	Tag    string      `json:"tag"`
	Object ghGitObject `json:"object"`
}

// ghGitObject is the object a git reference or annotated tag points to.
type ghGitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

// FetchReleaseMetadata retrieves from the GitHub API the metadata of the
// release the reference points to, resolving the commit the release tag points
// to and the repository license along the way.
func (b *GitHubBackend) FetchReleaseMetadata(ctx context.Context, ref *Reference) (*Metadata, error) {
	client, err := b.apiClient(ref)
	if err != nil {
		return nil, err
	}

	release := &ghRelease{}
	if err := ghAPIGet(ctx, client, ghReleasePath(ref.Repo, ref.Tag), release); err != nil {
		return nil, fmt.Errorf("fetching release data: %w", err)
	}

	commit, err := ghResolveCommit(ctx, client, ref.Repo, release.TagName)
	if err != nil {
		return nil, err
	}

	repository := &ghRepository{}
	if err := ghAPIGet(ctx, client, "repos/"+ref.Repo, repository); err != nil {
		return nil, fmt.Errorf("fetching repository data: %w", err)
	}

	name := release.Name
	if name == "" {
		name = release.TagName
	}

	return &Metadata{
		Name:        name,
		Tag:         release.TagName,
		URL:         release.HTMLURL,
		Commit:      commit,
		License:     repository.spdxLicense(),
		RepoURL:     ref.RepoURL(),
		Published:   release.PublishedAt,
		BackendData: release.Assets,
	}, nil
}

// FetchArtifactData gathers the data of the artifacts published in the release
// that md describes. The asset list stashed in the metadata by
// FetchReleaseMetadata is reused when present, avoiding a second API call.
func (b *GitHubBackend) FetchArtifactData(ctx context.Context, ref *Reference, md *Metadata) ([]*Artifact, error) {
	assets, ok := md.BackendData.([]ghAsset)
	if !ok {
		client, err := b.apiClient(ref)
		if err != nil {
			return nil, err
		}

		// Prefer the tag captured in the metadata so that a reference to the
		// latest release stays pinned to the release already fetched.
		tag := ref.Tag
		if md.Tag != "" {
			tag = md.Tag
		}
		release := &ghRelease{}
		if err := ghAPIGet(ctx, client, ghReleasePath(ref.Repo, tag), release); err != nil {
			return nil, fmt.Errorf("fetching release data: %w", err)
		}
		assets = release.Assets
	}

	artifacts := make([]*Artifact, 0, len(assets))
	for i := range assets {
		artifacts = append(artifacts, assets[i].artifact())
	}
	return artifacts, nil
}

// apiClient builds a client for the GitHub API instance serving the host the
// reference points to.
func (b *GitHubBackend) apiClient(ref *Reference) (*github.Client, error) {
	host := github.DefaultAPIHostname
	if ref.Host != githubPublicHost {
		host = ref.Host + "/api/v3"
	}
	// Reading the token from GITHUB_TOKEN mirrors the client's default
	// behavior; anonymous calls still work for public data when it is unset.
	opts := github.Options{
		Host:        host,
		TokenReader: &github.EnvTokenReader{VarName: "GITHUB_TOKEN"},
	}
	if b.caller != nil {
		opts.Caller = b.caller
	}
	client, err := github.NewClientWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("creating github client: %w", err)
	}
	return client, nil
}

// ghReleasePath returns the API path of the release cut from tag, or of the
// repository's latest release when tag is empty.
func ghReleasePath(repo, tag string) string {
	if tag == "" {
		return fmt.Sprintf("repos/%s/releases/latest", repo)
	}
	return fmt.Sprintf("repos/%s/releases/tags/%s", repo, tag)
}

// ghResolveCommit resolves the commit a tag points to, dereferencing annotated
// tags until it reaches the commit at the end of the chain. A tag deleted
// after its release was published resolves to an empty commit, not an error.
func ghResolveCommit(ctx context.Context, client *github.Client, repo, tag string) (string, error) {
	gitRef := &ghGitRef{}
	if err := ghAPIGet(ctx, client, fmt.Sprintf("repos/%s/git/ref/tags/%s", repo, tag), gitRef); err != nil {
		if errors.Is(err, errGitHubNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("fetching tag reference: %w", err)
	}

	sha, objectType := gitRef.Object.SHA, gitRef.Object.Type
	for range maxTagDereferences {
		if objectType != ghObjectTypeTag {
			break
		}
		gitTag := &ghGitTag{}
		if err := ghAPIGet(ctx, client, fmt.Sprintf("repos/%s/git/tags/%s", repo, sha), gitTag); err != nil {
			return "", fmt.Errorf("dereferencing annotated tag: %w", err)
		}
		sha, objectType = gitTag.Object.SHA, gitTag.Object.Type
	}
	if objectType == ghObjectTypeTag {
		return "", fmt.Errorf("tag %q still points to a tag object after %d dereferences", tag, maxTagDereferences)
	}
	return sha, nil
}

// ghAPIGet performs a GET request against the GitHub API and decodes the JSON
// response into the value pointed to by into. Requests answered with a 404 are
// reported with an error matching errGitHubNotFound.
func ghAPIGet(ctx context.Context, client *github.Client, path string, into any) error {
	resp, err := client.Call(ctx, http.MethodGet, path, nil)
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck // read-only body
	}
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %w", errGitHubNotFound, err)
		}
		return fmt.Errorf("querying the github API at %s: %w", path, err)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("decoding github API response from %s: %w", path, err)
	}
	return nil
}

// spdxLicense returns the SPDX identifier of the repository license, or the
// empty string when GitHub does not report a meaningful one.
func (r *ghRepository) spdxLicense() string {
	if r.License == nil || r.License.SPDXID == spdxNoAssertion {
		return ""
	}
	return r.License.SPDXID
}

// artifact maps the asset to the forge-neutral Artifact type. GitHub reports
// asset digests as "sha256:<hex>" strings; missing or unrecognized digests are
// skipped.
func (a *ghAsset) artifact() *Artifact {
	artifact := &Artifact{
		Name:        a.Name,
		DownloadURL: a.BrowserDownloadURL,
		Size:        a.Size,
		ContentType: a.ContentType,
		Digests:     map[sbom.HashAlgorithm]string{},
	}
	if algo, encoded, ok := strings.Cut(a.Digest, ":"); ok && algo == "sha256" && encoded != "" {
		artifact.Digests[sbom.HashAlgorithm_SHA256] = encoded
	}
	return artifact
}

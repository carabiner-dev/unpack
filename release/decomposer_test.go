// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// fakeBackend is a Backend implementation returning canned release data and,
// when set, injected errors.
type fakeBackend struct {
	md        *Metadata
	artifacts []*Artifact
	mdErr     error
	artErr    error
}

func (f *fakeBackend) FetchReleaseMetadata(_ context.Context, _ *Reference) (*Metadata, error) {
	if f.mdErr != nil {
		return nil, f.mdErr
	}
	return f.md, nil
}

func (f *fakeBackend) FetchArtifactData(_ context.Context, _ *Reference, _ *Metadata) ([]*Artifact, error) {
	if f.artErr != nil {
		return nil, f.artErr
	}
	return f.artifacts, nil
}

const testCommit = "aa5cd5be388dc45cd11b6d90b1eda7a1a4b34e71"

func testReference() *Reference {
	return &Reference{
		Forge: ForgeGitHub,
		Host:  "github.com",
		Repo:  "acme/widget",
		Tag:   "v1.0.0",
	}
}

func testMetadata() *Metadata {
	published := time.Date(2026, 5, 4, 12, 30, 0, 0, time.UTC)
	return &Metadata{
		Name:      "Widget v1.0.0",
		Tag:       "v1.0.0",
		URL:       "https://github.com/acme/widget/releases/tag/v1.0.0",
		Commit:    testCommit,
		License:   "Apache-2.0",
		RepoURL:   "https://github.com/acme/widget",
		Published: &published,
	}
}

func testArtifacts() []*Artifact {
	return []*Artifact{
		{
			Name:        "widget_linux_amd64.tar.gz",
			DownloadURL: "https://github.com/acme/widget/releases/download/v1.0.0/widget_linux_amd64.tar.gz",
			Size:        1024,
			ContentType: "application/gzip",
			Digests: map[sbom.HashAlgorithm]string{
				sbom.HashAlgorithm_SHA256: "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589",
			},
		},
		{
			Name:        "widget_darwin_arm64.tar.gz",
			DownloadURL: "https://github.com/acme/widget/releases/download/v1.0.0/widget_darwin_arm64.tar.gz",
			Size:        2048,
			ContentType: "application/gzip",
			Digests: map[sbom.HashAlgorithm]string{
				sbom.HashAlgorithm_SHA256: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
			},
		},
	}
}

// newTestDecomposer returns a decomposer with the fake backend registered as
// the github forge handler.
func newTestDecomposer(backend Backend) *Decomposer {
	d := NewDecomposer()
	d.RegisterBackend(ForgeGitHub, backend)
	return d
}

func TestExtractReleaseGraph(t *testing.T) {
	t.Parallel()
	d := newTestDecomposer(&fakeBackend{md: testMetadata(), artifacts: testArtifacts()})

	nl, err := d.ExtractRelease(t.Context(), testReference(), nil)
	require.NoError(t, err)
	require.NotNil(t, nl)
	require.Len(t, nl.GetNodes(), 3)

	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)
	root := roots[0]

	assert.Equal(t, sbom.Node_PACKAGE, root.GetType())
	assert.Equal(t, "widget", root.GetName())
	assert.Equal(t, "v1.0.0", root.GetVersion())
	assert.Equal(t, "Widget v1.0.0", root.GetDescription())
	assert.Equal(t, "https://github.com/acme/widget/releases/tag/v1.0.0", root.GetUrlHome())
	assert.Equal(t, []string{"Apache-2.0"}, root.GetLicenses())
	assert.Equal(t, "Apache-2.0", root.GetLicenseConcluded())
	assert.Equal(t, testCommit, root.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
	assert.Equal(t,
		"pkg:github/acme/widget@v1.0.0",
		root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)
	require.NotNil(t, root.GetReleaseDate())
	assert.Equal(t, *testMetadata().Published, root.GetReleaseDate().AsTime())

	require.Len(t, root.GetExternalReferences(), 1)
	vcs := root.GetExternalReferences()[0]
	assert.Equal(t, sbom.ExternalReference_VCS, vcs.GetType())
	assert.Equal(t, "git+https://github.com/acme/widget@"+testCommit, vcs.GetUrl())
	assert.Equal(t, testCommit, vcs.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])

	// The artifact nodes hang off the root through distributionArtifact edges.
	edge := nl.GetEdgeByType(root.GetId(), sbom.Edge_distributionArtifact)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 2)

	nodesByName := map[string]*sbom.Node{}
	for _, id := range edge.GetTo() {
		node := nl.GetNodeByID(id)
		require.NotNil(t, node)
		nodesByName[node.GetName()] = node
	}
	for _, artifact := range testArtifacts() {
		node, ok := nodesByName[artifact.Name]
		require.True(t, ok, "no node found for artifact %q", artifact.Name)
		assert.Equal(t, sbom.Node_FILE, node.GetType())
		assert.Equal(t, artifact.Name, node.GetFileName())
		assert.Equal(t, artifact.DownloadURL, node.GetUrlDownload())
		assert.Equal(t,
			artifact.Digests[sbom.HashAlgorithm_SHA256],
			node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
		)

		// Each artifact carries its own copy of the VCS reference.
		require.Len(t, node.GetExternalReferences(), 1)
		artifactVCS := node.GetExternalReferences()[0]
		assert.Equal(t, sbom.ExternalReference_VCS, artifactVCS.GetType())
		assert.Equal(t, vcs.GetUrl(), artifactVCS.GetUrl())
		assert.Equal(t, testCommit, artifactVCS.GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
		assert.NotSame(t, vcs, artifactVCS)
	}
}

func TestExtractRelease(t *testing.T) {
	t.Parallel()
	errMetadata := errors.New("metadata fetch failed")
	errArtifacts := errors.New("artifact fetch failed")

	for _, tc := range []struct {
		name    string
		ref     *Reference
		backend *fakeBackend
		check   func(t *testing.T, nl *sbom.NodeList, err error)
	}{
		{
			name: "enterprise-host-no-purl",
			ref: &Reference{
				Forge: ForgeGitHub, Host: "ghe.example.com", Repo: "acme/widget", Tag: "v1.0.0",
			},
			backend: &fakeBackend{md: testMetadata(), artifacts: testArtifacts()},
			check: func(t *testing.T, nl *sbom.NodeList, err error) {
				t.Helper()
				require.NoError(t, err)
				roots := nl.GetRootNodes()
				require.Len(t, roots, 1)
				assert.Empty(t, roots[0].GetIdentifiers())
			},
		},
		{
			name: "no-commit-no-hashes-no-vcs",
			ref:  testReference(),
			backend: &fakeBackend{
				md: &Metadata{
					Name: "Widget v1.0.0", Tag: "v1.0.0", License: "Apache-2.0",
				},
				artifacts: testArtifacts(),
			},
			check: func(t *testing.T, nl *sbom.NodeList, err error) {
				t.Helper()
				require.NoError(t, err)
				for _, node := range nl.GetNodes() {
					assert.Empty(t, node.GetExternalReferences())
					if node.GetType() == sbom.Node_PACKAGE {
						assert.Empty(t, node.GetHashes())
					}
				}
			},
		},
		{
			name: "no-license",
			ref:  testReference(),
			backend: &fakeBackend{
				md: &Metadata{Name: "Widget v1.0.0", Tag: "v1.0.0", Commit: testCommit},
			},
			check: func(t *testing.T, nl *sbom.NodeList, err error) {
				t.Helper()
				require.NoError(t, err)
				roots := nl.GetRootNodes()
				require.Len(t, roots, 1)
				assert.Empty(t, roots[0].GetLicenses())
				assert.Empty(t, roots[0].GetLicenseConcluded())
			},
		},
		{
			name: "latest-release-empty-tag",
			ref: &Reference{
				Forge: ForgeGitHub, Host: "github.com", Repo: "acme/widget",
			},
			backend: &fakeBackend{md: testMetadata(), artifacts: testArtifacts()},
			check: func(t *testing.T, nl *sbom.NodeList, err error) {
				t.Helper()
				require.NoError(t, err)
				roots := nl.GetRootNodes()
				require.Len(t, roots, 1)
				// The backend resolved the latest release to its tag.
				assert.Equal(t, "v1.0.0", roots[0].GetVersion())
				assert.Equal(t,
					"pkg:github/acme/widget@v1.0.0",
					roots[0].GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
				)
			},
		},
		{
			name: "unknown-forge",
			ref: &Reference{
				Forge: "codeberg", Host: "codeberg.org", Repo: "acme/widget", Tag: "v1.0.0",
			},
			backend: &fakeBackend{md: testMetadata()},
			check: func(t *testing.T, _ *sbom.NodeList, err error) {
				t.Helper()
				require.ErrorContains(t, err, `no backend registered for forge "codeberg"`)
			},
		},
		{
			name:    "invalid-reference",
			ref:     &Reference{Forge: ForgeGitHub, Host: "github.com"},
			backend: &fakeBackend{md: testMetadata()},
			check: func(t *testing.T, _ *sbom.NodeList, err error) {
				t.Helper()
				require.ErrorContains(t, err, "validating release reference")
			},
		},
		{
			name:    "metadata-error",
			ref:     testReference(),
			backend: &fakeBackend{mdErr: errMetadata},
			check: func(t *testing.T, _ *sbom.NodeList, err error) {
				t.Helper()
				require.ErrorIs(t, err, errMetadata)
				require.ErrorContains(t, err, "fetching release metadata")
			},
		},
		{
			name:    "artifact-error",
			ref:     testReference(),
			backend: &fakeBackend{md: testMetadata(), artErr: errArtifacts},
			check: func(t *testing.T, _ *sbom.NodeList, err error) {
				t.Helper()
				require.ErrorIs(t, err, errArtifacts)
				require.ErrorContains(t, err, "fetching release artifact data")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := newTestDecomposer(tc.backend)
			nl, err := d.ExtractRelease(t.Context(), tc.ref, nil)
			tc.check(t, nl, err)
		})
	}
}

func TestNewDecomposerDefaultBackends(t *testing.T) {
	t.Parallel()
	d := NewDecomposer()
	assert.Contains(t, d.backends, ForgeGitHub)
}

func TestExtractReleaseNilReference(t *testing.T) {
	t.Parallel()
	d := NewDecomposer()
	_, err := d.ExtractRelease(t.Context(), nil, nil)
	require.Error(t, err)
}

func TestDecomposerExtract(t *testing.T) {
	t.Parallel()
	t.Run("with-reference", func(t *testing.T) {
		t.Parallel()
		d := newTestDecomposer(&fakeBackend{md: testMetadata(), artifacts: testArtifacts()})

		dOpts, ok := d.DefaultOptions().(*Options)
		require.True(t, ok)
		dOpts.Reference = testReference()

		opts := &api.DecomposerOptions{}
		opts.SetDriverOptions(d, dOpts)

		nl, err := d.Extract(opts)
		require.NoError(t, err)
		require.Len(t, nl.GetRootNodes(), 1)
		assert.Equal(t, "widget", nl.GetRootNodes()[0].GetName())
	})

	t.Run("no-reference", func(t *testing.T) {
		t.Parallel()
		d := NewDecomposer()
		_, err := d.Extract(&api.DecomposerOptions{})
		require.ErrorContains(t, err, "no release reference")
	})

	t.Run("nil-options", func(t *testing.T) {
		t.Parallel()
		d := NewDecomposer()
		_, err := d.Extract(nil)
		require.Error(t, err)
	})
}

func TestDecomposerRequirements(t *testing.T) {
	t.Parallel()
	d := NewDecomposer()

	// Without a reference there is nothing to require.
	assert.Nil(t, d.Requirements(nil))
	assert.Nil(t, d.Requirements(&api.DecomposerOptions{}))

	// With a reference, the forge host must be reachable.
	opts := &api.DecomposerOptions{}
	opts.SetDriverOptions(d, &Options{Reference: testReference()})
	reqs := d.Requirements(opts)
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0].Description(), "github.com")
}

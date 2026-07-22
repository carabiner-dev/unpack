// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"time"

	"github.com/protobom/protobom/pkg/sbom"
)

// Metadata is the forge-neutral description of a software release. Backends
// fill it from their forge's API and the decomposer renders it into the root
// node of the release graph.
type Metadata struct {
	// Name is the human title of the release (may match the tag).
	Name string

	// Tag is the tag the release was cut from, doubling as its version.
	Tag string

	// URL points to the human-readable release page.
	URL string

	// Commit is the hex-encoded SHA-1 digest of the commit the release was
	// built from.
	Commit string

	// License is the SPDX identifier of the repository license, when the
	// forge reports one.
	License string

	// RepoURL is the https URL of the repository the release lives in.
	RepoURL string

	// Published is the timestamp the release was published at.
	Published *time.Time

	// BackendData is a private stash for the backend that produced the
	// metadata, letting FetchArtifactData reuse anything already retrieved
	// (e.g. the artifact list embedded in the release API response).
	BackendData any
}

// Artifact captures the data the forge reports about one of the artifacts
// published in a release.
type Artifact struct {
	// Name is the file name of the artifact.
	Name string

	// DownloadURL is the URL the artifact can be retrieved from.
	DownloadURL string

	// Size is the size of the artifact in bytes (0 when not reported).
	Size int64

	// ContentType is the media type the forge reports for the artifact.
	ContentType string

	// Digests are the hex-encoded hashes the forge reports for the artifact,
	// keyed by algorithm.
	Digests map[sbom.HashAlgorithm]string
}

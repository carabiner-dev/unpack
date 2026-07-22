// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import "context"

// Backend abstracts a release hosting system (a "forge") such as GitHub or
// GitLab. The release decomposer drives a backend in two steps: fetch the
// release metadata, then gather the data of the artifacts published in it.
//
// Implementations must be safe for concurrent use and keep no state between
// calls: anything FetchArtifactData needs from the metadata fetch travels in
// the Metadata struct (see Metadata.BackendData).
type Backend interface {
	// FetchReleaseMetadata retrieves from the forge the metadata of the
	// release the reference points to.
	FetchReleaseMetadata(ctx context.Context, ref *Reference) (*Metadata, error)

	// FetchArtifactData gathers the data of the artifacts published in the
	// release that md describes.
	FetchArtifactData(ctx context.Context, ref *Reference, md *Metadata) ([]*Artifact, error)
}

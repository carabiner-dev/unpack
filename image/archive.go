// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/protobom/protobom/pkg/sbom"
)

// extractArchive reads the image out of a docker-archive tarball and
// routes it through the same squash-and-scan pipeline as pulled images.
func (u *Unpacker) extractArchive(ctx context.Context, ref *Reference) ([]*sbom.NodeList, error) {
	refStr, nref, img, err := openArchiveImage(ref)
	if err != nil {
		return nil, err
	}
	nl, err := u.extractImage(ctx, refStr, nref, img)
	if err != nil {
		return nil, err
	}
	return []*sbom.NodeList{nl}, nil
}

// openArchiveImage loads the image from the archive along with the
// identity its node will carry. Ref selects the image in multi-image
// archives; without it, single-image archives identify through their
// RepoTags, falling back to the image digest for untagged archives,
// which then carry no purl or version.
func openArchiveImage(ref *Reference) (string, name.Reference, v1.Image, error) {
	if ref.Ref != "" {
		tag, err := name.NewTag(ref.Ref)
		if err != nil {
			return "", nil, nil, fmt.Errorf("parsing image reference %q: %w", ref.Ref, err)
		}
		img, err := tarball.ImageFromPath(ref.Archive, &tag)
		if err != nil {
			return "", nil, nil, fmt.Errorf("reading image %q from %q: %w", ref.Ref, ref.Archive, err)
		}
		return ref.Ref, tag, img, nil
	}

	manifest, err := tarball.LoadManifest(func() (io.ReadCloser, error) { return os.Open(ref.Archive) })
	if err != nil {
		return "", nil, nil, fmt.Errorf("reading manifest of %q: %w", ref.Archive, err)
	}
	if len(manifest) != 1 {
		return "", nil, nil, fmt.Errorf(
			"archive %q holds %d images, set Ref to select one", ref.Archive, len(manifest),
		)
	}

	if tags := manifest[0].RepoTags; len(tags) > 0 {
		tag, err := name.NewTag(tags[0])
		if err != nil {
			return "", nil, nil, fmt.Errorf("parsing archive tag %q: %w", tags[0], err)
		}
		img, err := tarball.ImageFromPath(ref.Archive, &tag)
		if err != nil {
			return "", nil, nil, fmt.Errorf("reading image from %q: %w", ref.Archive, err)
		}
		return tags[0], tag, img, nil
	}

	img, err := tarball.ImageFromPath(ref.Archive, nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("reading image from %q: %w", ref.Archive, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return "", nil, nil, fmt.Errorf("reading image digest: %w", err)
	}
	return digest.String(), nil, img, nil
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package image implements the unpacker that extracts dependency data from
// container images. It pulls an image by its OCI reference, or reads it
// from a docker-archive tarball, squashes its layers into a single
// filesystem, and routes that filesystem to the SystemPackages unpacker to
// read the installed-package databases.
package image

// SubjectType is the DecomposableSubject type routed to the image unpacker.
const SubjectType = "image"

// Reference is the DecomposableSubject consumed by the image unpacker: a
// container image addressed by an OCI reference, e.g. "alpine:3.24",
// "ghcr.io/org/app@sha256:..." or "registry.example.com/app:v1", or held
// in a docker-archive tarball on disk.
type Reference struct {
	// Ref is the OCI reference of the image or image index.
	Ref string

	// Archive is the path to a docker-archive tarball (the `docker save`
	// format) holding the image. When set, the image is read from the
	// archive instead of pulled from a registry. Ref, when also set,
	// selects the tagged image in a multi-image archive and provides the
	// reference identity; left empty, the identity comes from the
	// archive's RepoTags, or from the image digest when it has none.
	Archive string
}

// DecomposableType identifies this subject as a container image, routing it
// to the image unpacker through the registry.
func (r *Reference) DecomposableType() string { return SubjectType }

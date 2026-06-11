// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package image implements the unpacker that extracts dependency data from
// container images. It pulls an image by its OCI reference, squashes its
// layers into a single filesystem, and routes that filesystem to the
// SystemPackages unpacker to read the installed-package databases.
package image

// SubjectType is the DecomposableSubject type routed to the image unpacker.
const SubjectType = "image"

// Reference is the DecomposableSubject consumed by the image unpacker: a
// container image addressed by an OCI reference, e.g. "alpine:3.24",
// "ghcr.io/org/app@sha256:..." or "registry.example.com/app:v1".
type Reference struct {
	// Ref is the OCI reference of the image or image index.
	Ref string
}

// DecomposableType identifies this subject as a container image, routing it
// to the image unpacker through the registry.
func (r *Reference) DecomposableType() string { return SubjectType }

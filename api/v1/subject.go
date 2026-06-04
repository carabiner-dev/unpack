// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

// DecomposableSubject abstracts anything that can yield dependency data: a
// codebase, an SBOM, an artifact, a filesystem, a container image, etc. An
// Unpacker consumes subjects, and the registry routes a subject to the unpacker
// that knows how to process its type.
//
// The interface is intentionally minimal for now. Concrete subject types carry
// their own access details (a path, a reader, an image reference) which the
// unpacker that handles them type-asserts to.
type DecomposableSubject interface {
	// DecomposableType returns a stable identifier for the kind of subject
	// (e.g. "codebase", "sbom", "artifact"). The registry uses it to locate the
	// unpacker capable of processing the subject.
	DecomposableType() string
}

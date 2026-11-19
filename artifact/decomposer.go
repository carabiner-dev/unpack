// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"context"
	"io"
	"io/fs"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// HeaderSize is how many leading bytes of a file a decomposer gets to decide
// whether the file may be one of its artifacts. It covers every executable
// and archive magic number in common use.
const HeaderSize = 64

// Decomposer reads one flavor of artifact. It extends api.Decomposer with a
// content-based probe: the unpacker filters files through Matches, then asks
// ExtractArtifact to read the ones that pass.
type Decomposer interface {
	api.Decomposer

	// Name returns the short, stable name the decomposer is registered and
	// addressed by, such as "gobinary". Options refer to decomposers by it.
	Name() string

	// Matches reports whether a file may be one of the decomposer's
	// artifacts, judging by its metadata and its first HeaderSize bytes
	// (fewer for a shorter file). It is the cheap filter that keeps the
	// unpacker from reading every file in a filesystem; false positives
	// are fine, ExtractArtifact settles them.
	Matches(info fs.FileInfo, header []byte) bool

	// ExtractArtifact reads the artifact and returns its dependency graph:
	// the package the artifact was built from as the root, with the
	// packages built into it as descendants. The unpacker relates the
	// result to a node it creates for the file itself. Returning
	// (nil, nil) means the file turned out not to be one of the
	// decomposer's artifacts, which is not an error.
	ExtractArtifact(ra io.ReaderAt, path string, opts *api.DecomposerOptions) (*sbom.NodeList, error)
}

// ContextDecomposer is implemented by artifact decomposers that can be run
// with a context: the one the unpacker was given, which carries its
// caller's cancellation and whatever else it put there, such as a logger.
type ContextDecomposer interface {
	Decomposer

	// ExtractArtifactWithContext is ExtractArtifact, run with the
	// caller's context.
	ExtractArtifactWithContext(
		ctx context.Context, ra io.ReaderAt, path string, opts *api.DecomposerOptions,
	) (*sbom.NodeList, error)
}

// ExtractArtifactWithContext runs an artifact decomposer with a context
// when it takes one, and without when it does not.
func ExtractArtifactWithContext(
	ctx context.Context, d Decomposer, ra io.ReaderAt, path string, opts *api.DecomposerOptions,
) (*sbom.NodeList, error) {
	if cd, ok := d.(ContextDecomposer); ok {
		return cd.ExtractArtifactWithContext(ctx, ra, path, opts)
	}
	return d.ExtractArtifact(ra, path, opts)
}

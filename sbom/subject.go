// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"fmt"
	"io"
	"os"
)

// Subject is the DecomposableSubject consumed by the SBOM unpacker. It wraps a
// software bill of materials in any of the formats protobom understands. Either
// Reader or Path must be set; when both are set Reader takes precedence.
type Subject struct {
	// Reader is the SBOM document stream.
	Reader io.ReadSeeker
	// Path is the path to an SBOM document on disk. It is opened lazily by the
	// unpacker when Reader is not set.
	Path string
}

// DecomposableType identifies this subject as an SBOM, routing it to the SBOM
// unpacker through the registry.
func (s *Subject) DecomposableType() string { return "sbom" }

// open returns a reader for the subject's SBOM data along with a cleanup
// function the caller must invoke when done.
func (s *Subject) open() (io.ReadSeeker, func() error, error) {
	if s.Reader != nil {
		return s.Reader, func() error { return nil }, nil
	}
	if s.Path == "" {
		return nil, nil, fmt.Errorf("sbom subject has neither a reader nor a path")
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	return f, f.Close, nil
}

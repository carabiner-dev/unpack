// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"io/fs"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/unpack/filesystem/options"
	"github.com/carabiner-dev/unpack/filesystem/processors"
)

type FileProcessor interface {
	Process(*options.Options, fs.FS, *sbom.Node) error
}

// FileProcessorFactory is a function that creates a new FileProcessor instance.
type FileProcessorFactory func() FileProcessor

// FileProcessors is the list of available file processor factories.
// Each call produces a fresh instance to avoid shared mutable state.
var FileProcessors = map[string]FileProcessorFactory{
	"hash":    func() FileProcessor { return processors.NewHasher() },
	"license": func() FileProcessor { return processors.NewLicenseScanner() },
}

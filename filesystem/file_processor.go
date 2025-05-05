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

// FileProcessors is the list of available file processors
var FileProcessors = map[string]FileProcessor{
	"hash": processors.NewHasher(),
}

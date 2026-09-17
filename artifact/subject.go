// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package artifact implements the unpacker that reads dependency data
// embedded in built artifacts: executables carrying their build information,
// archives holding package metadata, and the like. It probes the files of a
// filesystem for the artifact flavors its decomposers understand and renders
// each artifact found as a graph rooted at the file.
package artifact

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// SubjectType is the DecomposableSubject type routed to the artifact unpacker.
const SubjectType = "artifact"

// Source is the DecomposableSubject consumed by the artifact unpacker: a
// filesystem holding artifacts, or a selection of files in one.
type Source interface {
	api.DecomposableSubject

	// FileSystem returns the filesystem the artifacts are read from.
	FileSystem() (fs.FS, error)

	// Paths lists the files to probe, relative to the filesystem root. Nil
	// means every regular file in the filesystem.
	Paths() []string
}

// File is a Source describing a single artifact on disk, for callers that
// point at one file: `unpack artifact ./bin/tool`.
type File struct {
	Path string
}

// DecomposableType identifies this subject as an artifact, routing it to the
// artifact unpacker through the registry.
func (f *File) DecomposableType() string { return SubjectType }

// FileSystem returns the file's directory as a filesystem.
func (f *File) FileSystem() (fs.FS, error) {
	if f.Path == "" {
		return nil, fmt.Errorf("artifact file subject has no path")
	}
	abs, err := filepath.Abs(f.Path)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", f.Path, err)
	}
	return os.DirFS(filepath.Dir(abs)), nil
}

// Paths returns the file's name, the one entry to probe in its directory.
func (f *File) Paths() []string {
	return []string{filepath.Base(f.Path)}
}

// Filesystem is a Source wrapping an arbitrary fs.FS: a squashed container
// image, a directory, an archive. Unpackers that crack such things open use
// it to route the inner filesystem to the artifact unpacker through the
// registry. Every regular file is probed unless Only narrows the scan.
type Filesystem struct {
	FS fs.FS

	// Only restricts the scan to these paths, relative to the FS root.
	Only []string
}

// DecomposableType identifies this subject as an artifact source, routing it
// to the artifact unpacker through the registry.
func (f *Filesystem) DecomposableType() string { return SubjectType }

// FileSystem returns the wrapped filesystem.
func (f *Filesystem) FileSystem() (fs.FS, error) {
	if f.FS == nil {
		return nil, fmt.Errorf("artifact filesystem subject has no fs.FS")
	}
	return f.FS, nil
}

// Paths returns the paths the scan is restricted to, or nil for all files.
func (f *Filesystem) Paths() []string { return f.Only }

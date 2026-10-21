// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	core "github.com/carabiner-dev/core/api/carabiner/core/v1"
)

// Codebase is the DecomposableSubject consumed by the dependencies unpacker. It
// points at a filesystem path that may contain one or more codebases; the
// unpacker scans it and runs the matching decomposers.
type Codebase struct {
	Path string
}

// DecomposableType identifies this subject as a codebase, routing it to the
// dependencies unpacker through the registry.
func (c *Codebase) DecomposableType() string { return "codebase" }

// CodebaseInfo contains information about a discovered codebase.
type CodebaseInfo struct {
	ID       string // canonical, e.g. "golang:services/api" ("golang:." at the root)
	Language string // e.g., "golang", "rust"
	Path     string // canonical path relative to the input directory ("." for the root)
	AbsPath  string // Absolute filesystem path
}

// GenerateCodebaseID creates a codebase ID from language and relative path in
// the platform's canonical form (core.CodebaseSourceID): forward slashes, no
// leading "./", no trailing slash, "." for the root. The same codebase gets
// the same id here and on the platform, which keys its record by it.
func GenerateCodebaseID(language, relativePath string) (string, error) {
	return core.CodebaseSourceID(language, relativePath)
}

// ParseCodebaseID parses a codebase ID into its language and canonical path,
// accepting the forms unpack used to write ("golang:./backend") as well as
// the canonical one.
func ParseCodebaseID(id string) (language, path string, err error) {
	return core.ParseCodebaseSourceID(id)
}

// CanonicalCodebasePath is core's canonical form of a path relative to the
// scanned directory, so a path unpack computed compares equal to a parsed id.
func CanonicalCodebasePath(relativePath string) (string, error) {
	return core.CanonicalCodebasePath(relativePath)
}

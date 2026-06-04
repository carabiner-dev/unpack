// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"errors"
	"fmt"
	"strings"
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
	ID       string // e.g., "golang:./services/api"
	Language string // e.g., "golang", "rust"
	Path     string // Relative path from input directory
	AbsPath  string // Absolute filesystem path
}

// GenerateCodebaseID creates a codebase ID from language and relative path.
func GenerateCodebaseID(language, relativePath string) string {
	return fmt.Sprintf("%s:%s", language, relativePath)
}

// ParseCodebaseID parses a codebase ID into its language and path components.
func ParseCodebaseID(id string) (language, path string, err error) {
	language, path, ok := strings.Cut(id, ":")
	if !ok {
		return "", "", errors.New("invalid codebase ID format: missing colon separator")
	}

	if language == "" {
		return "", "", errors.New("invalid codebase ID format: empty language")
	}
	if path == "" {
		return "", "", errors.New("invalid codebase ID format: empty path")
	}
	return language, path, nil
}

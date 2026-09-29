// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// This file models the GitHub dependency snapshot, the document the
// Dependency Submission API takes. sbt-dependency-submission writes one
// for an sbt build (githubGenerateSnapshot) before submitting it: every
// project of the build, per Scala version it cross-builds for, is a
// manifest listing what the project resolved.
//
// See https://docs.github.com/en/rest/dependency-graph/dependency-submission

// Snapshot is a dependency snapshot of a build at one commit.
type Snapshot struct {
	Version   int                  `json:"version"`
	Job       *Job                 `json:"job,omitempty"`
	Sha       string               `json:"sha"`
	Ref       string               `json:"ref"`
	Detector  *Detector            `json:"detector,omitempty"`
	Manifests map[string]*Manifest `json:"manifests"`
	Scanned   string               `json:"scanned,omitempty"`
}

// Job identifies the workflow run that generated the snapshot.
type Job struct {
	Correlator string `json:"correlator"`
	ID         string `json:"id"`
	HTMLURL    string `json:"html_url,omitempty"`
}

// Detector names the tool that generated the snapshot.
type Detector struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Version string `json:"version"`
}

// Manifest is the resolution of one project of the build. sbt names it
// after the project's module, as organization:name:revision with the
// name cross-versioned (org.scala-lang:scala3-compiler_3:3.9.0).
type Manifest struct {
	Name     string                     `json:"name"`
	File     *FileInfo                  `json:"file,omitempty"`
	Metadata map[string]any             `json:"metadata,omitempty"`
	Resolved map[string]*DependencyNode `json:"resolved"`
}

// FileInfo points to the build file the manifest was read from, relative
// to the workspace root.
type FileInfo struct {
	SourceLocation string `json:"source_location,omitempty"`
}

// The relationships and scopes a resolved dependency can have.
const (
	RelationshipDirect   = "direct"
	RelationshipIndirect = "indirect"

	ScopeRuntime     = "runtime"
	ScopeDevelopment = "development"
)

// DependencyNode is one resolved module. Its dependencies are keys of the
// manifest's resolved map, as sbt references modules
// (organization:name:revision).
type DependencyNode struct {
	PackageURL   string         `json:"package_url"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Relationship string         `json:"relationship,omitempty"`
	Scope        string         `json:"scope,omitempty"`
	Dependencies []string       `json:"dependencies,omitempty"`
}

// ReadSnapshot reads a dependency snapshot from a file.
func ReadSnapshot(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening dependency snapshot: %w", err)
	}
	defer f.Close() //nolint:errcheck

	s, err := ParseSnapshot(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return s, nil
}

// ParseSnapshot decodes a dependency snapshot. Only version 0 of the
// format exists; anything else is refused rather than half read.
func ParseSnapshot(r io.Reader) (*Snapshot, error) {
	s := &Snapshot{}
	if err := json.NewDecoder(r).Decode(s); err != nil {
		return nil, fmt.Errorf("decoding dependency snapshot: %w", err)
	}
	if s.Version != 0 {
		return nil, fmt.Errorf("unsupported dependency snapshot version %d", s.Version)
	}
	if len(s.Manifests) == 0 {
		return nil, errors.New("dependency snapshot has no manifests")
	}
	return s, nil
}

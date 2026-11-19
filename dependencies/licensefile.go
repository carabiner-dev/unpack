// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"context"
	"os"
	"path/filepath"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/unpack/internal/logging"
	"github.com/carabiner-dev/unpack/license/detect"
)

// This file gives a codebase the license its license file states.
//
// Decomposers read a project's license from its manifest, where the
// ecosystem has a place for one: Cargo.toml, package.json, a POM. Go,
// Ruby and sbt have none, and where there is one it is often left empty.
// The project still says how it is licensed, the way every project does,
// in a LICENSE file, and that is read here for all of them.

// applyLicenseFile sets the license of the codebase's license file on the
// root nodes that have none. What a decomposer read from a manifest
// stands: it is the project stating its license as data, where the file
// is a text that has to be recognized.
func applyLicenseFile(ctx context.Context, nl *sbom.NodeList, cbPath string) {
	unlicensed := []*sbom.Node{}
	for _, root := range nl.GetRootNodes() {
		if len(root.GetLicenses()) == 0 {
			unlicensed = append(unlicensed, root)
		}
	}
	if len(unlicensed) == 0 {
		return
	}

	id, file := findLicenseFile(cbPath)
	if id == "" {
		return
	}
	for _, root := range unlicensed {
		root.Licenses = []string{id}
	}
	logging.FromContext(ctx).Debug("license of the codebase read from its license file",
		"codebase", cbPath, "file", file, "license", id)
}

// findLicenseFile looks for a license file in the directory and then in
// the ones above it, the nearest first, and returns the license it holds
// and the path of the file.
//
// A codebase in a subdirectory of a repository is licensed by the
// repository's file when it has none of its own, so the search goes up,
// and stops at the root of the git repository: what lies above is
// another project's, or nobody's. A directory in no repository is
// searched alone.
func findLicenseFile(dir string) (id, path string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", ""
	}
	top := repositoryRoot(abs)
	for {
		if id, name := detect.Dir(os.DirFS(abs)); id != "" {
			return id, filepath.Join(abs, name)
		}
		parent := filepath.Dir(abs)
		if top == "" || abs == top || parent == abs {
			return "", ""
		}
		abs = parent
	}
}

// repositoryRoot returns the root of the git repository a directory is
// in, the nearest directory at or above it holding a .git, and nothing
// when it is in none. A .git may be a file: a worktree or a submodule has
// one.
func repositoryRoot(dir string) string {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

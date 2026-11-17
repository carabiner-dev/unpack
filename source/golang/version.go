// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file names the version of a module read from its source tree, the
// way the go command would name that commit to anything depending on it.
//
// A commit carrying a version tag is that version. Any other is known by
// a pseudo-version (https://go.dev/ref/mod#pseudo-versions), built from
// the commit's time and hash and the version tagged before it in its
// history: v1.2.4-0.20260102150405-abcdefabcdef after v1.2.3, and
// v0.0.0-20260102150405-abcdefabcdef when nothing was tagged before. It
// sorts between the two releases it sits between and is what a go.mod
// requiring the commit would say, so the module's identifier is one Go
// tooling recognizes.

// pseudoVersionRevisionLength is how much of a commit hash a pseudo-version
// carries.
const pseudoVersionRevisionLength = 12

// moduleVersion returns the version of the module at modPath for the
// commit the options describe.
//
// The pseudo-version needs the commit's time. Options that do not carry
// it describe no commit this can name, and the version they state stands
// as it is: one a caller chose, or the one embedded in a binary, which
// the go command already wrote in this form.
func moduleVersion(modPath string, opts *api.DecomposerOptions) string {
	if opts.CommitHash == "" || opts.CommitTime.IsZero() {
		return opts.Version
	}
	_, pathMajor, ok := module.SplitPathVersion(modPath)
	if !ok {
		return opts.Version
	}

	if tagged := highestVersionTag(opts.Tags, pathMajor); tagged != "" {
		return tagged
	}

	revision := opts.CommitHash
	if len(revision) > pseudoVersionRevisionLength {
		revision = revision[:pseudoVersionRevisionLength]
	}
	return module.PseudoVersion(
		module.PathMajorPrefix(pathMajor),
		highestVersionTag(opts.AncestorTags, pathMajor),
		opts.CommitTime.UTC(), revision,
	)
}

// highestVersionTag picks, out of a commit's tags, the highest that is a
// version of the module: a canonical semantic version, of the major
// version the module's path states (v0 or v1 when it states none). Other
// tags, and versions of another major, say nothing about this module.
func highestVersionTag(tags []string, pathMajor string) string {
	highest := ""
	for _, tag := range tags {
		if !semver.IsValid(tag) || semver.Canonical(tag) != tag || module.IsPseudoVersion(tag) {
			continue
		}
		if module.CheckPathMajor(tag, pathMajor) != nil {
			continue
		}
		if highest == "" || semver.Compare(tag, highest) > 0 {
			highest = tag
		}
	}
	return highest
}

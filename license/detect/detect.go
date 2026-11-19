// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package detect tells which license a text is, and finds the license
// file of a directory.
//
// It is apart from the license package, which only knows names: telling a
// license from its text takes a classifier and the corpus of texts it
// compares with, some megabytes a program that only normalizes names has
// no use for.
package detect

import (
	"io"
	"io/fs"
	"strings"
	"sync"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"

	"github.com/carabiner-dev/unpack/license"
)

// FileNames are the names a project's license file goes by, the likeliest
// first. They are matched whatever their case.
var FileNames = []string{
	"LICENSE",
	"LICENSE.md",
	"LICENSE.txt",
	"LICENCE",
	"LICENCE.md",
	"LICENCE.txt",
	"COPYING",
	"COPYING.md",
	"COPYING.txt",
}

// maxSize is how much of a license file is read. The longest of the
// common licenses, the GPL, is some 35 kB.
const maxSize = 256 * 1024

var (
	shared     *classifier.Classifier
	sharedOnce sync.Once
)

// get returns the classifier, built on first use: loading its corpus
// takes long enough not to do it for a run that classifies nothing.
func get() *classifier.Classifier {
	sharedOnce.Do(func() {
		if c, err := assets.DefaultClassifier(); err == nil {
			shared = c
		}
	})
	return shared
}

// Text returns the SPDX identifier of the license a text is, and nothing
// for a text that is not recognized as one.
func Text(content []byte) string {
	c := get()
	if c == nil || len(content) == 0 {
		return ""
	}
	for _, m := range c.Match(content).Matches {
		if m.MatchType == "License" {
			return license.Normalize(m.Name, "")
		}
	}
	return ""
}

// IsFileName says whether a file name is one a license file goes by.
func IsFileName(name string) bool {
	for _, known := range FileNames {
		if strings.EqualFold(name, known) {
			return true
		}
	}
	return false
}

// Dir looks for a license file at the top of a directory and returns the
// SPDX identifier of the license it holds and the name of the file. The
// names are tried in the order of FileNames, and a file that is not
// recognized as a license is passed over for the next. It returns nothing
// when the directory has no license file that is.
func Dir(fsys fs.FS) (id, file string) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return "", ""
	}
	for _, known := range FileNames {
		for _, entry := range entries {
			if !entry.Type().IsRegular() || !strings.EqualFold(entry.Name(), known) {
				continue
			}
			f, err := fsys.Open(entry.Name())
			if err != nil {
				continue
			}
			content, err := io.ReadAll(io.LimitReader(f, maxSize))
			f.Close() //nolint:errcheck,gosec // read-only file
			if err != nil {
				continue
			}
			if id := Text(content); id != "" {
				return id, entry.Name()
			}
		}
	}
	return "", ""
}

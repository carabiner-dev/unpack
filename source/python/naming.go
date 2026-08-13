// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package python implements dependency extraction for Python codebases.
//
// This file holds the naming rules. Python package names are compared after
// normalization (PEP 503): Flask, flask and flask are all one project, and
// an index, a lockfile and a wheel may each spell the name differently.
// Every name read from project metadata goes through NormalizeName before it
// is used as an identity anywhere.
package python

import (
	"regexp"
	"strings"
)

// nameSeparators is the run of characters PEP 503 collapses to a dash.
var nameSeparators = regexp.MustCompile(`[-_.]+`)

// NormalizeName returns the canonical form of a Python package name: every
// run of dashes, underscores and dots becomes one dash, and the result is
// lowercased. This is the form purls and lockfile lookups use.
func NormalizeName(name string) string {
	return strings.ToLower(nameSeparators.ReplaceAllString(strings.TrimSpace(name), "-"))
}

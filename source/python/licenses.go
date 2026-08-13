// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"strings"

	"github.com/carabiner-dev/unpack/license"
)

// licensesFromMetadata reads a licence out of the three places Python
// package metadata states one, best first. The same tiers appear in the
// PyPI API and in an installed distribution's METADATA, so both readers
// share this triage.
//
// The declared expression (PEP 639) is already SPDX and wins outright. The
// free-text field is next: old packages stuff anything in it, including the
// whole licence text, so a value that does not look like a short name is
// ignored. Trove classifiers come last, and only the ones the licence
// catalog can name: a classifier such as "Apache Software License" does not
// say which version, and guessing would be inventing data.
func licensesFromMetadata(expression, freeText string, classifiers []string) []string {
	if expression != "" {
		return []string{license.Normalize(expression, "")}
	}

	if text := strings.TrimSpace(freeText); text != "" && text != "UNKNOWN" &&
		len(text) <= 100 && !strings.ContainsAny(text, "\n\r") {
		return []string{license.Normalize(text, "")}
	}

	licenses := []string{}
	for _, classifier := range classifiers {
		name, found := strings.CutPrefix(classifier, "License :: ")
		if !found {
			continue
		}
		// The interesting part is the last segment: the OSI Approved
		// grouping in the middle names nothing.
		if i := strings.LastIndex(name, " :: "); i >= 0 {
			name = name[i+4:]
		}
		// Only a name the catalog recognizes becomes a licence. Normalize
		// returns its input unchanged when it has no answer, and a raw
		// trove name is not a licence identifier.
		if normalized := license.Normalize(name, ""); normalized != name {
			licenses = append(licenses, normalized)
		}
	}
	return licenses
}

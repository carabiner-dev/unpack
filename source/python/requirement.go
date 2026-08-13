// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"regexp"
	"strings"
)

// This file takes apart requirement strings (PEP 508), the form manifests
// declare dependencies in: "requests[socks]>=2.28 ; python_version < '3.12'".
// Only the parts an edge needs are kept — the name, the extras and the
// marker. Version constraints are input to a resolver, and everything here
// reads resolved data.

// requirementPattern matches the head of a requirement: the name and the
// optional extras list. What follows is a version specifier, a "@ url"
// direct reference, or nothing.
var requirementPattern = regexp.MustCompile(
	`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?`)

// requirement is a declared dependency, reduced to what an edge needs,
// plus the two things a requirement can state about where its content
// comes from: an exact pin, or a direct URL.
type requirement struct {
	Name   string
	Extras []string
	Marker string

	// Version is set when the requirement pins exactly one version:
	// "name==1.2.3". A range constrains a resolver, it does not name a
	// version, so ranges leave this empty.
	Version string

	// URL is set for a direct reference: "name @ https://..." or a git+
	// URL.
	URL string
}

// exactPin matches a specifier that names exactly one version: == or ===
// with no wildcard and no further clauses.
var exactPin = regexp.MustCompile(`^===?\s*([^\s,*]+)$`)

// parseRequirement reads one PEP 508 requirement string.
func parseRequirement(line string) (*requirement, error) {
	spec, marker, _ := strings.Cut(line, ";")
	spec = strings.TrimSpace(spec)

	m := requirementPattern.FindStringSubmatch(spec)
	if m == nil {
		return nil, fmt.Errorf("%q is not a requirement", line)
	}

	req := &requirement{
		Name:   NormalizeName(m[1]),
		Marker: strings.TrimSpace(marker),
	}
	for _, extra := range strings.Split(m[2], ",") {
		if extra = strings.TrimSpace(extra); extra != "" {
			req.Extras = append(req.Extras, NormalizeName(extra))
		}
	}

	rest := strings.TrimSpace(spec[len(m[0]):])
	switch {
	case strings.HasPrefix(rest, "@"):
		req.URL = strings.TrimSpace(strings.TrimPrefix(rest, "@"))
	default:
		if pin := exactPin.FindStringSubmatch(rest); pin != nil {
			req.Version = pin[1]
		}
	}
	return req, nil
}

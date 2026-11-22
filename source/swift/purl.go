// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"net/url"
	"regexp"
	"strings"

	purl "github.com/package-url/packageurl-go"
)

// This file names packages the way the Swift Package Manager does in the
// SBOMs it generates (SE-0509), so that a package read from a lockfile
// and the same package in SwiftPM's own SBOM are one name. The rules are
// those of its PURL.swift.

var scpLocation = regexp.MustCompile(`^[^@]+@([^:]+):([^/]+)(?:/.*)?$`)

// Namespace returns the namespace of the pin's purl: for a registry
// package its scope, for a repository its host and the first element of
// its path (github.com/apple), and none for a local one.
//
// The first element only, as SwiftPM has it: a repository nested deeper,
// in a subgroup, is named by its host and top group.
func (p *Pin) Namespace() string {
	if p.Kind == KindRegistry {
		scope, _, _ := strings.Cut(p.Identity, ".")
		return scope
	}
	location := p.Location
	if location == "" || strings.HasPrefix(location, "/") {
		return ""
	}
	if match := scpLocation.FindStringSubmatch(location); match != nil {
		return match[1] + "/" + match[2]
	}
	if parsed, err := url.Parse(location); err == nil && parsed.Hostname() != "" {
		elements := []string{}
		for _, element := range strings.Split(parsed.Path, "/") {
			if element != "" {
				elements = append(elements, element)
			}
		}
		if len(elements) >= 2 {
			return parsed.Hostname() + "/" + elements[0]
		}
	}
	return ""
}

// PURLName returns the name of the pin's purl: its identity, and for a
// registry package its name without the scope.
func (p *Pin) PURLName() string {
	if p.Kind == KindRegistry {
		if _, name, found := strings.Cut(p.Identity, "."); found && name != "" {
			return name
		}
	}
	return p.Identity
}

// PURL returns the purl of the pin: pkg:swift, with the namespace and
// name above and the component version. A package of a local repository
// has no namespace and its path as a qualifier.
func (p *Pin) PURL() string {
	var qualifiers purl.Qualifiers
	if strings.HasPrefix(p.Location, "/") {
		qualifiers = purl.Qualifiers{{Key: "path", Value: p.Location}}
	}
	return purl.NewPackageURL(purl.TypeSwift, p.Namespace(), p.PURLName(), p.ComponentVersion(), qualifiers, "").ToString()
}

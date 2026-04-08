// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"regexp"
	"strings"
)

var propertyPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// maxInterpolationPasses limits recursive property resolution to prevent infinite loops.
const maxInterpolationPasses = 10

// InterpolatePOM resolves all ${...} property placeholders in a POM.
// It modifies the POM in place and returns it for convenience.
func InterpolatePOM(pom *POM) *POM {
	props := buildPropertyMap(pom)

	// Resolve property-in-property references iteratively
	props = resolvePropertyRefs(props)

	// Interpolate all string fields
	pom.GroupID = interpolateString(pom.GroupID, props)
	pom.ArtifactID = interpolateString(pom.ArtifactID, props)
	pom.Version = interpolateString(pom.Version, props)
	pom.Name = interpolateString(pom.Name, props)
	pom.Description = interpolateString(pom.Description, props)
	pom.URL = interpolateString(pom.URL, props)

	for i := range pom.Dependencies {
		interpolateDependency(&pom.Dependencies[i], props)
	}

	if pom.DependencyManagement != nil {
		for i := range pom.DependencyManagement.Dependencies {
			interpolateDependency(&pom.DependencyManagement.Dependencies[i], props)
		}
	}

	for i := range pom.Licenses {
		pom.Licenses[i].Name = interpolateString(pom.Licenses[i].Name, props)
		pom.Licenses[i].URL = interpolateString(pom.Licenses[i].URL, props)
	}

	return pom
}

// interpolateDependency resolves property placeholders in a Dependency.
func interpolateDependency(dep *Dependency, props map[string]string) {
	dep.GroupID = interpolateString(dep.GroupID, props)
	dep.ArtifactID = interpolateString(dep.ArtifactID, props)
	dep.Version = interpolateString(dep.Version, props)
	dep.Scope = interpolateString(dep.Scope, props)
	dep.Type = interpolateString(dep.Type, props)
	dep.Classifier = interpolateString(dep.Classifier, props)
	dep.Optional = interpolateString(dep.Optional, props)
}

// interpolateString replaces ${property.name} tokens in s using the given properties.
// Unresolvable placeholders are left as-is.
func interpolateString(s string, props map[string]string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return propertyPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-1] // strip ${ and }
		if val, ok := props[key]; ok {
			return val
		}
		return match // leave unresolved
	})
}

// buildPropertyMap constructs the full property map for a POM,
// including implicit project.* properties.
func buildPropertyMap(pom *POM) map[string]string {
	props := make(map[string]string)

	// User-defined properties first
	for k, v := range pom.Properties {
		props[k] = v
	}

	// Implicit project properties (these can be overridden by user props)
	setIfNotEmpty := func(key, val string) {
		if val != "" {
			if _, exists := props[key]; !exists {
				props[key] = val
			}
		}
	}

	setIfNotEmpty("project.groupId", pom.EffectiveGroupID())
	setIfNotEmpty("project.artifactId", pom.ArtifactID)
	setIfNotEmpty("project.version", pom.EffectiveVersion())
	setIfNotEmpty("project.name", pom.Name)
	setIfNotEmpty("project.description", pom.Description)
	setIfNotEmpty("project.url", pom.URL)
	setIfNotEmpty("project.packaging", pom.Packaging)

	// Shorthand aliases
	setIfNotEmpty("groupId", pom.EffectiveGroupID())
	setIfNotEmpty("artifactId", pom.ArtifactID)
	setIfNotEmpty("version", pom.EffectiveVersion())

	if pom.Parent != nil {
		setIfNotEmpty("project.parent.groupId", pom.Parent.GroupID)
		setIfNotEmpty("project.parent.artifactId", pom.Parent.ArtifactID)
		setIfNotEmpty("project.parent.version", pom.Parent.Version)
	}

	return props
}

// resolvePropertyRefs iteratively resolves property values that reference
// other properties (e.g., a.version = ${b.version}). Stops after
// maxInterpolationPasses or when no more substitutions are made.
func resolvePropertyRefs(props map[string]string) map[string]string {
	for range maxInterpolationPasses {
		changed := false
		for k, v := range props {
			if !strings.Contains(v, "${") {
				continue
			}
			resolved := interpolateString(v, props)
			if resolved != v {
				props[k] = resolved
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return props
}

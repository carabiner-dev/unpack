// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterpolatePOM(t *testing.T) {
	t.Parallel()
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	InterpolatePOM(pom)

	// Property references in dependency versions should be resolved
	require.Equal(t, "33.0.0-jre", pom.Dependencies[0].Version)
	require.Equal(t, "3.14.0", pom.Dependencies[1].Version)

	// DependencyManagement should also be resolved
	require.Equal(t, "33.0.0-jre", pom.DependencyManagement.Dependencies[0].Version)
}

func TestInterpolateProjectProperties(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "my-app",
		Version:    "3.0.0",
		Properties: Properties{
			"my.group": "${project.groupId}",
		},
		Dependencies: []Dependency{
			{GroupID: "${my.group}", ArtifactID: "dep", Version: "${project.version}"},
		},
	}

	InterpolatePOM(pom)

	require.Equal(t, "com.example", pom.Dependencies[0].GroupID)
	require.Equal(t, "3.0.0", pom.Dependencies[0].Version)
}

func TestInterpolateParentProperties(t *testing.T) {
	t.Parallel()
	pom := &POM{
		Parent: &Parent{
			GroupID:    "com.parent",
			ArtifactID: "parent-pom",
			Version:    "5.0.0",
		},
		ArtifactID: "child",
		Dependencies: []Dependency{
			{GroupID: "${project.parent.groupId}", ArtifactID: "dep", Version: "${project.parent.version}"},
		},
	}

	InterpolatePOM(pom)

	require.Equal(t, "com.parent", pom.Dependencies[0].GroupID)
	require.Equal(t, "5.0.0", pom.Dependencies[0].Version)
}

func TestInterpolateRecursiveProperties(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Properties: Properties{
			"base.version": "2.0",
			"full.version": "${base.version}.1",
		},
		Dependencies: []Dependency{
			{GroupID: "g", ArtifactID: "a", Version: "${full.version}"},
		},
	}

	InterpolatePOM(pom)

	require.Equal(t, "2.0.1", pom.Dependencies[0].Version)
}

func TestInterpolateUnresolvable(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "g", ArtifactID: "a", Version: "${unknown.property}"},
		},
	}

	InterpolatePOM(pom)

	// Unresolvable properties should be left as-is
	require.Equal(t, "${unknown.property}", pom.Dependencies[0].Version)
}

func TestInterpolateString(t *testing.T) {
	t.Parallel()
	props := map[string]string{
		"a": "hello",
		"b": "world",
	}

	require.Equal(t, "hello", interpolateString("${a}", props))
	require.Equal(t, "hello-world", interpolateString("${a}-${b}", props))
	require.Equal(t, "no-props", interpolateString("no-props", props))
	require.Equal(t, "${missing}", interpolateString("${missing}", props))
	require.Empty(t, interpolateString("", props))
}

func TestInterpolateInheritedGroupAndVersion(t *testing.T) {
	t.Parallel()
	// When groupId/version are empty, they should come from parent
	pom := &POM{
		Parent: &Parent{
			GroupID: "com.parent",
			Version: "1.0.0",
		},
		ArtifactID: "child",
		Dependencies: []Dependency{
			{GroupID: "g", ArtifactID: "a", Version: "${project.groupId}"},
		},
	}

	InterpolatePOM(pom)

	require.Equal(t, "com.parent", pom.Dependencies[0].Version)
}

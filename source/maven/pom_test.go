// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePomXML(t *testing.T) {
	t.Parallel()
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	require.Equal(t, "com.example", pom.GroupID)
	require.Equal(t, "simple-app", pom.ArtifactID)
	require.Equal(t, "1.0.0", pom.Version)
	require.Equal(t, "jar", pom.Packaging)
	require.Equal(t, "Simple Test App", pom.Name)
}

func TestParsePomXMLDependencies(t *testing.T) {
	t.Parallel()
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	require.Len(t, pom.Dependencies, 5)

	// Guava with property reference
	require.Equal(t, "com.google.guava", pom.Dependencies[0].GroupID)
	require.Equal(t, "guava", pom.Dependencies[0].ArtifactID)
	require.Equal(t, "${guava.version}", pom.Dependencies[0].Version)

	// commons-lang3
	require.Equal(t, "org.apache.commons", pom.Dependencies[1].GroupID)
	require.Equal(t, "${commons.version}", pom.Dependencies[1].Version)

	// junit with test scope
	require.Equal(t, "junit", pom.Dependencies[2].GroupID)
	require.Equal(t, "test", pom.Dependencies[2].Scope)
	require.Equal(t, "test", pom.Dependencies[2].EffectiveScope())

	// servlet-api with provided scope
	require.Equal(t, "provided", pom.Dependencies[3].EffectiveScope())

	// jsr305 optional
	require.Equal(t, "true", pom.Dependencies[4].Optional)
	require.True(t, pom.Dependencies[4].IsOptional())
}

func TestParsePomXMLProperties(t *testing.T) {
	t.Parallel()
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	require.Len(t, pom.Properties, 3)
	require.Equal(t, "33.0.0-jre", pom.Properties["guava.version"])
	require.Equal(t, "3.14.0", pom.Properties["commons.version"])
	require.Equal(t, "UTF-8", pom.Properties["project.build.sourceEncoding"])
}

func TestParsePomXMLLicenses(t *testing.T) {
	t.Parallel()
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	require.Len(t, pom.Licenses, 1)
	require.Equal(t, "Apache License, Version 2.0", pom.Licenses[0].Name)
	require.Equal(t, "https://www.apache.org/licenses/LICENSE-2.0", pom.Licenses[0].URL)
}

func TestParsePomXMLDependencyManagement(t *testing.T) {
	t.Parallel()
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	require.NotNil(t, pom.DependencyManagement)
	require.Len(t, pom.DependencyManagement.Dependencies, 1)

	managed := pom.DependencyManagement.Dependencies[0]
	require.Equal(t, "com.google.guava", managed.GroupID)
	require.Equal(t, "guava", managed.ArtifactID)
	require.Len(t, managed.Exclusions, 1)
	require.Equal(t, "com.google.code.findbugs", managed.Exclusions[0].GroupID)
	require.Equal(t, "jsr305", managed.Exclusions[0].ArtifactID)
}

func TestParsePomXMLData(t *testing.T) {
	t.Parallel()
	data := []byte(`<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>test.group</groupId>
    <artifactId>test-artifact</artifactId>
    <version>2.0.0</version>
</project>`)

	pom, err := ParsePomXMLData(data)
	require.NoError(t, err)
	require.Equal(t, "test.group", pom.GroupID)
	require.Equal(t, "test-artifact", pom.ArtifactID)
	require.Equal(t, "2.0.0", pom.Version)
}

func TestParsePomXMLDataInvalid(t *testing.T) {
	t.Parallel()
	_, err := ParsePomXMLData([]byte("not xml"))
	require.Error(t, err)
}

func TestDependencyKey(t *testing.T) {
	t.Parallel()
	d := Dependency{GroupID: "com.google.guava", ArtifactID: "guava"}
	require.Equal(t, "com.google.guava:guava", d.Key())
}

func TestDependencyDefaults(t *testing.T) {
	t.Parallel()
	d := Dependency{}
	require.Equal(t, "compile", d.EffectiveScope())
	require.Equal(t, "jar", d.EffectiveType())
	require.False(t, d.IsOptional())
}

func TestExclusionMatches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		excl    Exclusion
		group   string
		art     string
		matches bool
	}{
		{"exact", Exclusion{"g", "a"}, "g", "a", true},
		{"no match", Exclusion{"g", "a"}, "g", "b", false},
		{"wildcard group", Exclusion{"*", "a"}, "any", "a", true},
		{"wildcard artifact", Exclusion{"g", "*"}, "g", "any", true},
		{"wildcard both", Exclusion{"*", "*"}, "any", "any", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.matches, tc.excl.Matches(tc.group, tc.art))
		})
	}
}

func TestEffectiveGroupIDAndVersion(t *testing.T) {
	t.Parallel()

	// With own values
	pom := &POM{GroupID: "own.group", Version: "1.0"}
	require.Equal(t, "own.group", pom.EffectiveGroupID())
	require.Equal(t, "1.0", pom.EffectiveVersion())

	// Inherit from parent
	pom = &POM{Parent: &Parent{GroupID: "parent.group", Version: "2.0"}}
	require.Equal(t, "parent.group", pom.EffectiveGroupID())
	require.Equal(t, "2.0", pom.EffectiveVersion())

	// Own overrides parent
	pom = &POM{GroupID: "own.group", Version: "1.0", Parent: &Parent{GroupID: "parent.group", Version: "2.0"}}
	require.Equal(t, "own.group", pom.EffectiveGroupID())
	require.Equal(t, "1.0", pom.EffectiveVersion())
}

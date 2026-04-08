// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeTransitivity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		parentScope string
		depScope    string
		want        string
	}{
		// compile parent
		{"compile+compile", ScopeCompile, ScopeCompile, ScopeCompile},
		{"compile+runtime", ScopeCompile, ScopeRuntime, ScopeRuntime},
		{"compile+provided", ScopeCompile, ScopeProvided, ""},
		{"compile+test", ScopeCompile, ScopeTest, ""},

		// provided parent
		{"provided+compile", ScopeProvided, ScopeCompile, ScopeProvided},
		{"provided+runtime", ScopeProvided, ScopeRuntime, ScopeProvided},
		{"provided+provided", ScopeProvided, ScopeProvided, ""},

		// runtime parent
		{"runtime+compile", ScopeRuntime, ScopeCompile, ScopeRuntime},
		{"runtime+runtime", ScopeRuntime, ScopeRuntime, ScopeRuntime},
		{"runtime+provided", ScopeRuntime, ScopeProvided, ""},

		// test parent
		{"test+compile", ScopeTest, ScopeCompile, ScopeTest},
		{"test+runtime", ScopeTest, ScopeRuntime, ScopeTest},
		{"test+provided", ScopeTest, ScopeProvided, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scopeTransitivity(tc.parentScope, tc.depScope)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestBuildSimpleTree(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib-a", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "lib-b", Version: "2.0"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	// Root + 2 dependencies
	require.Len(t, dt.resolved, 3)
	require.Contains(t, dt.resolved, "com.example:app")
	require.Contains(t, dt.resolved, "com.dep:lib-a")
	require.Contains(t, dt.resolved, "com.dep:lib-b")

	require.Equal(t, "1.0", dt.resolved["com.dep:lib-a"].Coordinate.Version)
	require.Equal(t, ScopeCompile, dt.resolved["com.dep:lib-a"].Scope)
}

func TestBuildTreeScopeFiltering(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "compile-dep", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "test-dep", Version: "1.0", Scope: ScopeTest},
			{GroupID: "com.dep", ArtifactID: "provided-dep", Version: "1.0", Scope: ScopeProvided},
		},
	}

	// Default options: no test, no provided
	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	require.Contains(t, dt.resolved, "com.dep:compile-dep")
	require.NotContains(t, dt.resolved, "com.dep:test-dep")
	require.NotContains(t, dt.resolved, "com.dep:provided-dep")

	// With test scope included
	opts := Options{IncludeTest: true}
	dt = NewDependencyTree(pom, nil, &opts)
	err = dt.Build()
	require.NoError(t, err)
	require.Contains(t, dt.resolved, "com.dep:test-dep")
}

func TestBuildTreeOptionalFiltering(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "normal", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "optional", Version: "1.0", Optional: "true"},
		},
	}

	// Default: no optional
	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)
	require.NotContains(t, dt.resolved, "com.dep:optional")

	// With optional included
	opts := Options{IncludeOptional: true}
	dt = NewDependencyTree(pom, nil, &opts)
	err = dt.Build()
	require.NoError(t, err)
	require.Contains(t, dt.resolved, "com.dep:optional")
}

func TestBuildTreeNearestWins(t *testing.T) {
	t.Parallel()
	// Simulate: app -> lib-a -> shared:1.0, app -> lib-b -> shared:2.0
	// Both at depth 2, so first encountered (lib-a's shared:1.0) wins
	// But since we can't set up transitive deps without a resolver,
	// test with two direct deps of the same groupId:artifactId
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "lib", Version: "2.0"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	// First version wins
	require.Equal(t, "1.0", dt.resolved["com.dep:lib"].Coordinate.Version)
}

func TestBuildTreeExclusions(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				{
					GroupID:    "com.dep",
					ArtifactID: "parent-lib",
					Version:    "1.0",
					Exclusions: []Exclusion{
						{GroupID: "com.excluded", ArtifactID: "lib"},
					},
				},
			},
		},
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "parent-lib"},
			{GroupID: "com.excluded", ArtifactID: "lib", Version: "1.0"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	// parent-lib is resolved
	require.Contains(t, dt.resolved, "com.dep:parent-lib")
	// excluded lib should still be resolved since exclusions only apply to transitive deps
	// (direct dependencies are not affected by exclusions from other dependencies)
	require.Contains(t, dt.resolved, "com.excluded:lib")
}

func TestBuildTreeDependencyManagement(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				{GroupID: "com.dep", ArtifactID: "managed", Version: "5.0.0"},
			},
		},
		Dependencies: []Dependency{
			// No version specified, should come from management
			{GroupID: "com.dep", ArtifactID: "managed"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	require.Equal(t, "5.0.0", dt.resolved["com.dep:managed"].Coordinate.Version)
}

func TestToNodeList(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Licenses:   []License{{Name: "Apache-2.0"}},
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib", Version: "2.0"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	nl, err := dt.ToNodeList(nil)
	require.NoError(t, err)

	// Root node + 1 dependency
	require.Len(t, nl.GetRootElements(), 1)

	nodes := nl.GetNodes()
	require.Len(t, nodes, 2)

	// Check root node
	root := nl.GetRootElements()[0]
	rootNode := nl.GetNodeByID(root)
	require.Equal(t, "app", rootNode.GetName())
	require.Equal(t, "1.0.0", rootNode.GetVersion())
	require.Contains(t, rootNode.GetIdentifiers(), int32(1)) // PURL
	require.Equal(t, "pkg:maven/com.example/app@1.0.0", rootNode.GetIdentifiers()[int32(1)])
}

func TestToNodeListEdgeTypes(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "compile-dep", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "test-dep", Version: "1.0", Scope: ScopeTest},
		},
	}

	opts := Options{IncludeTest: true}
	dt := NewDependencyTree(pom, nil, &opts)
	err := dt.Build()
	require.NoError(t, err)

	nl, err := dt.ToNodeList(nil)
	require.NoError(t, err)

	// Should have 3 nodes: root + 2 deps
	require.Len(t, nl.GetNodes(), 3)
}

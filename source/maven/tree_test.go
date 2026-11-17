// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
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

// TestBuildTreeManagementOverridesTransitive checks that the project's
// dependencyManagement decides the version and scope of what its
// dependencies bring in, and only fills in what its own declarations
// leave out.
func TestBuildTreeManagementOverridesTransitive(t *testing.T) {
	t.Parallel()

	pomFor := func(artifact, version, deps string) string {
		return `<?xml version="1.0"?>
<project>
    <groupId>com.dep</groupId>
    <artifactId>` + artifact + `</artifactId>
    <version>` + version + `</version>
    <dependencies>` + deps + `</dependencies>
</project>`
	}
	dep := func(artifact, version, scope string) string {
		s := "<dependency><groupId>com.dep</groupId><artifactId>" + artifact + "</artifactId><version>" + version + "</version>"
		if scope != "" {
			s += "<scope>" + scope + "</scope>"
		}
		return s + "</dependency>"
	}
	url := func(artifact, version string) string {
		return "https://repo.test/com/dep/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
	}

	resolver := newTestResolver(map[string]string{
		url("lib", "1.0"): pomFor("lib", "1.0",
			dep("pinned", "1.0", "")+dep("scoped", "1.0", "")+dep("unmanaged", "1.0", "")+dep("testonly", "1.0", "test")),
		url("pinned", "3.0"):    pomFor("pinned", "3.0", ""),
		url("scoped", "1.0"):    pomFor("scoped", "1.0", ""),
		url("unmanaged", "1.0"): pomFor("unmanaged", "1.0", ""),
		url("direct", "1.0"):    pomFor("direct", "1.0", ""),
	})

	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				{GroupID: "com.dep", ArtifactID: "pinned", Version: "3.0"},
				{GroupID: "com.dep", ArtifactID: "scoped", Scope: ScopeRuntime},
				{GroupID: "com.dep", ArtifactID: "direct", Version: "2.0"},
				{GroupID: "com.dep", ArtifactID: "testonly", Version: "2.0", Scope: ScopeCompile},
			},
		},
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "direct", Version: "1.0"},
		},
	}

	dt := NewDependencyTree(pom, resolver, &defaultOptions)
	require.NoError(t, dt.Build())

	// The managed version replaces the one lib's POM states.
	require.Equal(t, "3.0", dt.resolved["com.dep:pinned"].Coordinate.Version)
	require.Contains(t, dt.edges["com.dep:lib:1.0"], dt.resolved["com.dep:pinned"].Coordinate.String())

	// And so does the managed scope, the version left as stated.
	require.Equal(t, "1.0", dt.resolved["com.dep:scoped"].Coordinate.Version)
	require.Equal(t, ScopeRuntime, dt.resolved["com.dep:scoped"].Scope)

	// What management does not name is untouched.
	require.Equal(t, "1.0", dt.resolved["com.dep:unmanaged"].Coordinate.Version)

	// A version the project declares itself stands.
	require.Equal(t, "1.0", dt.resolved["com.dep:direct"].Coordinate.Version)

	// A dependency that is not transitive as declared stays out, whatever
	// scope the project manages it to.
	require.NotContains(t, dt.resolved, "com.dep:testonly")
}

// TestBuildTreeInheritsParentDependencies checks that what a parent POM
// declares is a dependency of the POMs that inherit from it: of the
// project, and of a dependency with a parent of its own.
func TestBuildTreeInheritsParentDependencies(t *testing.T) {
	t.Parallel()

	const header = `<?xml version="1.0"?><project>`
	dep := func(artifact, version string) string {
		return "<dependency><groupId>com.dep</groupId><artifactId>" + artifact + "</artifactId><version>" + version + "</version></dependency>"
	}
	url := func(artifact, version string) string {
		return "https://repo.test/com/dep/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
	}

	resolver := newTestResolver(map[string]string{
		// The project's parent brings in a logging library, with its
		// version in a property the project overrides.
		url("app-parent", "1.0"): header + `<groupId>com.dep</groupId><artifactId>app-parent</artifactId><version>1.0</version>
<packaging>pom</packaging>
<properties><logging.version>1.0</logging.version></properties>
<dependencies>` + dep("logging", "${logging.version}") + `</dependencies></project>`,
		// A dependency whose own parent brings something in too.
		url("lib", "1.0"): header + `<artifactId>lib</artifactId>
<parent><groupId>com.dep</groupId><artifactId>lib-parent</artifactId><version>1.0</version></parent></project>`,
		url("lib-parent", "1.0"): header + `<groupId>com.dep</groupId><artifactId>lib-parent</artifactId><version>1.0</version>
<packaging>pom</packaging>
<dependencies>` + dep("annotations", "4.0") + `</dependencies></project>`,
		url("logging", "2.0"):     header + `<groupId>com.dep</groupId><artifactId>logging</artifactId><version>2.0</version></project>`,
		url("annotations", "4.0"): header + `<groupId>com.dep</groupId><artifactId>annotations</artifactId><version>4.0</version></project>`,
	})

	pom, err := resolver.ResolveEffectivePOM(&POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Parent:     &Parent{GroupID: "com.dep", ArtifactID: "app-parent", Version: "1.0"},
		Properties: Properties{"logging.version": "2.0"},
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib", Version: "1.0"},
		},
	})
	require.NoError(t, err)

	dt := NewDependencyTree(pom, resolver, &defaultOptions)
	require.NoError(t, dt.Build())

	// From the project's parent, under the root, at the version the
	// project's own property gives it.
	require.Equal(t, "2.0", dt.resolved["com.dep:logging"].Coordinate.Version)
	require.Equal(t,
		[]string{"com.dep:lib:1.0", "com.dep:logging:2.0"},
		dt.edges["com.example:app:1.0.0"])

	// From the dependency's parent, under the dependency.
	require.Equal(t, []string{"com.dep:annotations:4.0"}, dt.edges["com.dep:lib:1.0"])
}

// TestBuildTreeEdgesToMediatedDependency checks that every dependency
// requiring an artifact gets an edge to it, at the version mediation chose
// and not the one each asked for, unless it excludes the artifact.
func TestBuildTreeEdgesToMediatedDependency(t *testing.T) {
	t.Parallel()

	dep := func(artifact, version string) string {
		return "<dependency><groupId>com.dep</groupId><artifactId>" + artifact + "</artifactId><version>" + version + "</version></dependency>"
	}
	pomFor := func(artifact, version, deps string) string {
		return `<?xml version="1.0"?><project><groupId>com.dep</groupId><artifactId>` + artifact +
			`</artifactId><version>` + version + `</version><dependencies>` + deps + `</dependencies></project>`
	}
	url := func(artifact, version string) string {
		return "https://repo.test/com/dep/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
	}

	resolver := newTestResolver(map[string]string{
		url("a", "1.0"):      pomFor("a", "1.0", dep("shared", "1.0")),
		url("b", "1.0"):      pomFor("b", "1.0", dep("shared", "2.0")+dep("direct", "2.0")),
		url("c", "1.0"):      pomFor("c", "1.0", dep("shared", "1.0")),
		url("shared", "1.0"): pomFor("shared", "1.0", ""),
		url("direct", "1.0"): pomFor("direct", "1.0", ""),
	})

	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "a", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "b", Version: "1.0"},
			{
				GroupID: "com.dep", ArtifactID: "c", Version: "1.0",
				Exclusions: []Exclusion{{GroupID: "com.dep", ArtifactID: "shared"}},
			},
			{GroupID: "com.dep", ArtifactID: "direct", Version: "1.0"},
		},
	}

	dt := NewDependencyTree(pom, resolver, &defaultOptions)
	require.NoError(t, dt.Build())

	// One version of each, the nearest and then the first declared.
	require.Equal(t, "1.0", dt.resolved["com.dep:shared"].Coordinate.Version)
	require.Equal(t, "1.0", dt.resolved["com.dep:direct"].Coordinate.Version)

	// a reached shared first; b asked for another version and depends on
	// the one chosen, as it does on the version of direct the project
	// declares.
	require.Equal(t, []string{"com.dep:shared:1.0"}, dt.edges["com.dep:a:1.0"])
	require.Equal(t, []string{"com.dep:shared:1.0", "com.dep:direct:1.0"}, dt.edges["com.dep:b:1.0"])

	// c is declared with shared excluded: no edge.
	require.Empty(t, dt.edges["com.dep:c:1.0"])

	// The root's edges are its own declarations, each once.
	require.Equal(t,
		[]string{"com.dep:a:1.0", "com.dep:b:1.0", "com.dep:c:1.0", "com.dep:direct:1.0"},
		dt.edges["com.example:app:1.0.0"])

	// And the graph holds each package once, with both parents related.
	nl, err := dt.ToNodeList(nil)
	require.NoError(t, err)
	require.Len(t, nl.GetNodes(), 6)
	parents := 0
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			if nl.GetNodeByID(to).GetName() == "shared" {
				parents++
			}
		}
	}
	require.Equal(t, 2, parents)
}

// TestBuildTreeManagedExclusionsMerge checks that the exclusions the
// project manages for a transitive dependency add to the ones the
// dependency is declared with, where each alone would leave one in.
func TestBuildTreeManagedExclusionsMerge(t *testing.T) {
	t.Parallel()

	dep := func(artifact, version, extra string) string {
		return "<dependency><groupId>com.dep</groupId><artifactId>" + artifact + "</artifactId><version>" + version + "</version>" + extra + "</dependency>"
	}
	pomFor := func(artifact, version, deps string) string {
		return `<?xml version="1.0"?><project><groupId>com.dep</groupId><artifactId>` + artifact +
			`</artifactId><version>` + version + `</version><dependencies>` + deps + `</dependencies></project>`
	}
	url := func(artifact, version string) string {
		return "https://repo.test/com/dep/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
	}

	resolver := newTestResolver(map[string]string{
		// lib declares middle with one exclusion of its own.
		url("lib", "1.0"): pomFor("lib", "1.0", dep("middle", "1.0",
			"<exclusions><exclusion><groupId>com.dep</groupId><artifactId>own-excluded</artifactId></exclusion></exclusions>")),
		url("middle", "1.0"): pomFor("middle", "1.0",
			dep("own-excluded", "1.0", "")+dep("managed-excluded", "1.0", "")+dep("kept", "1.0", "")),
		url("kept", "1.0"): pomFor("kept", "1.0", ""),
	})

	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				{
					GroupID: "com.dep", ArtifactID: "middle",
					Exclusions: []Exclusion{{GroupID: "com.dep", ArtifactID: "managed-excluded"}},
				},
			},
		},
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib", Version: "1.0"},
		},
	}

	dt := NewDependencyTree(pom, resolver, &defaultOptions)
	require.NoError(t, dt.Build())

	require.Contains(t, dt.resolved, "com.dep:middle")
	require.Contains(t, dt.resolved, "com.dep:kept")
	require.NotContains(t, dt.resolved, "com.dep:own-excluded")
	require.NotContains(t, dt.resolved, "com.dep:managed-excluded")
	require.Equal(t, []string{"com.dep:kept:1.0"}, dt.edges["com.dep:middle:1.0"])

	// The POM read from the repository keeps the exclusions it states.
	libPOM, err := resolver.FetchPOM("com.dep", "lib", "1.0")
	require.NoError(t, err)
	require.Len(t, libPOM.Dependencies[0].Exclusions, 1)
}

// TestBuildTreeScopeWidens checks that a dependency first reached through
// a test dependency, and so resolved for tests, takes the scope of a later
// path that needs it for compilation, and passes it down to what it
// brings in: both what was already resolved under it and what was still
// queued. One the project declares itself keeps its declared scope.
func TestBuildTreeScopeWidens(t *testing.T) {
	t.Parallel()

	dep := func(artifact, version string) string {
		return "<dependency><groupId>com.dep</groupId><artifactId>" + artifact + "</artifactId><version>" + version + "</version></dependency>"
	}
	pomFor := func(artifact, deps string) string {
		return `<?xml version="1.0"?><project><groupId>com.dep</groupId><artifactId>` + artifact +
			`</artifactId><version>1.0</version><dependencies>` + deps + `</dependencies></project>`
	}
	url := func(artifact string) string {
		return "https://repo.test/com/dep/" + artifact + "/1.0/" + artifact + "-1.0.pom"
	}

	resolver := newTestResolver(map[string]string{
		// The test dependency reaches early at depth 2, late at depth 2
		// too, and the project's own test dependency.
		url("testlib"): pomFor("testlib", dep("early", "1.0")+dep("late", "1.0")+dep("only-tests", "1.0")),
		// The compile dependency reaches late directly, and early one
		// level further down, after early's own dependency was resolved.
		url("lib"):         pomFor("lib", dep("late", "1.0")+dep("middle", "1.0")+dep("direct-test", "1.0")),
		url("middle"):      pomFor("middle", dep("early", "1.0")),
		url("early"):       pomFor("early", dep("early-child", "1.0")),
		url("late"):        pomFor("late", dep("late-child", "1.0")),
		url("early-child"): pomFor("early-child", ""),
		url("late-child"):  pomFor("late-child", ""),
		url("only-tests"):  pomFor("only-tests", ""),
		url("direct-test"): pomFor("direct-test", ""),
	})

	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "testlib", Version: "1.0", Scope: ScopeTest},
			{GroupID: "com.dep", ArtifactID: "lib", Version: "1.0"},
			{GroupID: "com.dep", ArtifactID: "direct-test", Version: "1.0", Scope: ScopeTest},
		},
	}

	opts := Options{IncludeTest: true}
	dt := NewDependencyTree(pom, resolver, &opts)
	require.NoError(t, dt.Build())

	scope := func(artifact string) string {
		rd, ok := dt.resolved["com.dep:"+artifact]
		require.True(t, ok, "%s is not resolved", artifact)
		return rd.Scope
	}

	// Widened after its own dependency was resolved under it.
	require.Equal(t, ScopeCompile, scope("early"))
	require.Equal(t, ScopeCompile, scope("early-child"))

	// Widened while its own dependency was still queued.
	require.Equal(t, ScopeCompile, scope("late"))
	require.Equal(t, ScopeCompile, scope("late-child"))

	// Nothing but tests needs these.
	require.Equal(t, ScopeTest, scope("testlib"))
	require.Equal(t, ScopeTest, scope("only-tests"))

	// Declared for tests by the project itself: that stands, though lib
	// would bring it in for compilation.
	require.Equal(t, ScopeTest, scope("direct-test"))

	// And in the graph, only what stayed test-scoped is a dev dependency.
	nl, err := dt.ToNodeList(nil)
	require.NoError(t, err)
	dev := []string{}
	for _, e := range nl.GetEdges() {
		if e.GetType() != sbom.Edge_devDependency {
			continue
		}
		for _, to := range e.GetTo() {
			dev = append(dev, nl.GetNodeByID(to).GetName())
		}
	}
	require.ElementsMatch(t, []string{"testlib", "only-tests", "direct-test", "direct-test"}, dev)
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

// TestToNodeListVersionOverride checks that a version given in the
// options, as when it is read from git, renames the root and leaves its
// dependencies attached.
func TestToNodeListVersionOverride(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "lib", Version: "2.0"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	require.NoError(t, dt.Build())

	nl, err := dt.ToNodeList(&api.DecomposerOptions{Version: "v2.0.0"})
	require.NoError(t, err)

	require.Len(t, nl.GetRootElements(), 1)
	rootNode := nl.GetNodeByID(nl.GetRootElements()[0])
	require.Equal(t, "v2.0.0", rootNode.GetVersion())
	require.Equal(t, "pkg:maven/com.example/app@v2.0.0", rootNode.GetIdentifiers()[int32(1)])

	// Root node + 1 dependency, related to the root.
	require.Len(t, nl.GetNodes(), 2)
	require.Len(t, nl.GetEdges(), 1)
	require.Equal(t, rootNode.GetId(), nl.GetEdges()[0].GetFrom())
	require.Len(t, nl.GetEdges()[0].GetTo(), 1)
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

func TestAddBuildPlugins(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.dep", ArtifactID: "main-dep", Version: "1.0"},
		},
		Build: &Build{
			Plugins: []Plugin{
				{GroupID: "org.apache.maven.plugins", ArtifactID: "maven-compiler-plugin", Version: "3.11.0"},
				{ArtifactID: "maven-shade-plugin", Version: "3.5.1"}, // no groupId, should default
				{ArtifactID: "maven-surefire-plugin"},                // no version, should be skipped
			},
		},
	}

	opts := Options{IncludeBuild: true}
	dt := NewDependencyTree(pom, nil, &opts)
	err := dt.Build()
	require.NoError(t, err)

	dt.AddBuildPlugins()

	nl, err := dt.ToNodeList(nil)
	require.NoError(t, err)

	// root + 1 dep + 2 plugins (surefire skipped: no version)
	require.Len(t, nl.GetNodes(), 4)

	// Check that plugins are present
	var pluginNames []string
	for _, node := range nl.GetNodes() {
		if node.GetName() == "maven-compiler-plugin" || node.GetName() == "maven-shade-plugin" {
			pluginNames = append(pluginNames, node.GetName())
		}
	}
	require.Len(t, pluginNames, 2)
	require.Contains(t, pluginNames, "maven-compiler-plugin")
	require.Contains(t, pluginNames, "maven-shade-plugin")
}

func TestRepoURLForDep(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		repos   []Repository
		version string
		want    string
	}{
		{
			"release version no repos",
			nil,
			"1.0.0",
			"",
		},
		{
			"snapshot version no repos",
			nil,
			"1.0-SNAPSHOT",
			"",
		},
		{
			"snapshot version with snapshot repo",
			[]Repository{{
				ID:        "snapshots",
				URL:       "https://repo.example.com/snapshots",
				Snapshots: &RepositoryPolicy{Enabled: "true"},
			}},
			"1.0-SNAPSHOT",
			"https://repo.example.com/snapshots",
		},
		{
			"snapshot version with trailing slash",
			[]Repository{{
				ID:        "snapshots",
				URL:       "https://repo.example.com/snapshots/",
				Snapshots: &RepositoryPolicy{Enabled: "true"},
			}},
			"1.0-SNAPSHOT",
			"https://repo.example.com/snapshots",
		},
		{
			"release version with snapshot repo",
			[]Repository{{
				ID:        "snapshots",
				URL:       "https://repo.example.com/snapshots",
				Snapshots: &RepositoryPolicy{Enabled: "true"},
				Releases:  &RepositoryPolicy{Enabled: "false"},
			}},
			"1.0.0",
			"",
		},
		{
			"snapshot version with snapshots disabled",
			[]Repository{{
				ID:        "releases-only",
				URL:       "https://repo.example.com/releases",
				Snapshots: &RepositoryPolicy{Enabled: "false"},
			}},
			"1.0-SNAPSHOT",
			"",
		},
		{
			"snapshot version with maven central repo",
			[]Repository{{
				ID:        "central",
				URL:       "https://repo1.maven.org/maven2",
				Snapshots: &RepositoryPolicy{Enabled: "true"},
			}},
			"1.0-SNAPSHOT",
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pom := &POM{
				GroupID:      "com.example",
				ArtifactID:   "app",
				Version:      "1.0.0",
				Repositories: tc.repos,
			}
			dt := NewDependencyTree(pom, nil, &defaultOptions)
			got := dt.repoURLForDep(tc.version)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestBuildTreeSnapshotRepoURL(t *testing.T) {
	t.Parallel()
	pom := &POM{
		GroupID:    "com.example",
		ArtifactID: "app",
		Version:    "1.0.0",
		Repositories: []Repository{{
			ID:        "apache-snapshots",
			Name:      "Apache Snapshots",
			URL:       "https://repository.apache.org/content/repositories/snapshots/",
			Snapshots: &RepositoryPolicy{Enabled: "true"},
			Releases:  &RepositoryPolicy{Enabled: "false"},
		}},
		Dependencies: []Dependency{
			{GroupID: "org.apache.commons", ArtifactID: "commons-lang3", Version: "3.21.0-SNAPSHOT"},
			{GroupID: "org.apache.commons", ArtifactID: "commons-text", Version: "1.13.0"},
		},
	}

	dt := NewDependencyTree(pom, nil, &defaultOptions)
	err := dt.Build()
	require.NoError(t, err)

	// SNAPSHOT dep should have the repo URL
	snapshotDep := dt.resolved["org.apache.commons:commons-lang3"]
	require.NotNil(t, snapshotDep)
	require.Equal(t, "https://repository.apache.org/content/repositories/snapshots", snapshotDep.Coordinate.RepoURL)
	require.Contains(t, snapshotDep.Coordinate.PURL(), "repository_url=https://repository.apache.org/content/repositories/snapshots")

	// Release dep should NOT have a repo URL
	releaseDep := dt.resolved["org.apache.commons:commons-text"]
	require.NotNil(t, releaseDep)
	require.Empty(t, releaseDep.Coordinate.RepoURL)
	require.NotContains(t, releaseDep.Coordinate.PURL(), "repository_url")
}

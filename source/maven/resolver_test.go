// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAgentImpl implements khttp.AgentImplementation for testing.
type fakeAgentImpl struct {
	responses map[string]string // URL -> response body
}

func (f *fakeAgentImpl) SendGetRequest(_ *http.Client, url string) (*http.Response, error) {
	body, ok := f.responses[url]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("")),
		}, fmt.Errorf("not found: %s", url)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func (f *fakeAgentImpl) SendPostRequest(_ *http.Client, _ string, _ []byte, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeAgentImpl) SendHeadRequest(_ *http.Client, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func newTestResolver(responses map[string]string) *Resolver {
	r := NewResolver(&Options{
		RepoURL:     "https://repo.test",
		Concurrency: 1,
	})
	r.Agent = r.Agent.WithRetries(0)
	r.Agent.SetImplementation(&fakeAgentImpl{responses: responses})
	return r
}

func TestResolverPomURL(t *testing.T) {
	t.Parallel()
	r := NewResolver(&Options{RepoURL: "https://repo.test"})
	url := r.pomURL("org.apache.commons", "commons-lang3", "3.14.0")
	require.Equal(t, "https://repo.test/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom", url)
}

func TestResolverMetadataURL(t *testing.T) {
	t.Parallel()
	r := NewResolver(&Options{RepoURL: "https://repo.test"})
	url := r.metadataURL("org.apache.commons", "commons-lang3")
	require.Equal(t, "https://repo.test/org/apache/commons/commons-lang3/maven-metadata.xml", url)
}

func TestResolverFetchPOM(t *testing.T) {
	t.Parallel()
	pomXML := `<?xml version="1.0"?>
<project>
    <groupId>com.test</groupId>
    <artifactId>test-lib</artifactId>
    <version>1.0.0</version>
</project>`

	r := newTestResolver(map[string]string{
		"https://repo.test/com/test/test-lib/1.0.0/test-lib-1.0.0.pom": pomXML,
	})

	pom, err := r.FetchPOM("com.test", "test-lib", "1.0.0")
	require.NoError(t, err)
	require.Equal(t, "com.test", pom.GroupID)
	require.Equal(t, "1.0.0", pom.Version)

	// Second call should be cached
	pom2, err := r.FetchPOM("com.test", "test-lib", "1.0.0")
	require.NoError(t, err)
	require.Equal(t, pom, pom2)
}

func TestResolverFetchPOMNotFound(t *testing.T) {
	t.Parallel()
	r := newTestResolver(map[string]string{})
	_, err := r.FetchPOM("com.missing", "lib", "1.0")
	require.Error(t, err)
}

func TestResolverFetchAvailableVersions(t *testing.T) {
	t.Parallel()
	metadataXML := `<?xml version="1.0"?>
<metadata>
    <groupId>com.test</groupId>
    <artifactId>lib</artifactId>
    <versioning>
        <latest>2.0.0</latest>
        <release>2.0.0</release>
        <versions>
            <version>1.0.0</version>
            <version>1.1.0</version>
            <version>2.0.0</version>
        </versions>
    </versioning>
</metadata>`

	r := newTestResolver(map[string]string{
		"https://repo.test/com/test/lib/maven-metadata.xml": metadataXML,
	})

	versions, err := r.FetchAvailableVersions("com.test", "lib")
	require.NoError(t, err)
	require.Equal(t, []string{"1.0.0", "1.1.0", "2.0.0"}, versions)
}

func TestResolverResolveVersionRange(t *testing.T) {
	t.Parallel()
	metadataXML := `<?xml version="1.0"?>
<metadata>
    <versioning>
        <versions>
            <version>1.0</version>
            <version>1.5</version>
            <version>2.0</version>
        </versions>
    </versioning>
</metadata>`

	r := newTestResolver(map[string]string{
		"https://repo.test/g/a/maven-metadata.xml": metadataXML,
	})

	v, err := r.ResolveVersionRange("g", "a", "[1.0,2.0)")
	require.NoError(t, err)
	require.Equal(t, "1.5", v)
}

func TestMergeParent(t *testing.T) {
	t.Parallel()
	parent := &POM{
		GroupID:    "com.parent",
		Version:    "1.0.0",
		Properties: Properties{"parent.prop": "pval", "shared": "parent"},
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				{GroupID: "g", ArtifactID: "managed", Version: "1.0"},
				{GroupID: "g", ArtifactID: "only-parent", Version: "2.0"},
			},
		},
		Licenses: []License{{Name: "Apache-2.0"}},
	}

	child := &POM{
		ArtifactID: "child",
		Properties: Properties{"child.prop": "cval", "shared": "child"},
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				{GroupID: "g", ArtifactID: "managed", Version: "2.0"},
			},
		},
	}

	merged := MergeParent(child, parent)

	// GroupID inherited from parent
	require.Equal(t, "com.parent", merged.GroupID)

	// Properties merged, child wins on conflicts
	require.Equal(t, "pval", merged.Properties["parent.prop"])
	require.Equal(t, "cval", merged.Properties["child.prop"])
	require.Equal(t, "child", merged.Properties["shared"])

	// DependencyManagement: child's "managed" wins, parent's "only-parent" inherited
	require.Len(t, merged.DependencyManagement.Dependencies, 2)

	// Licenses inherited
	require.Len(t, merged.Licenses, 1)
	require.Equal(t, "Apache-2.0", merged.Licenses[0].Name)
}

func TestResolveEffectivePOM(t *testing.T) {
	t.Parallel()
	parentPOM := `<?xml version="1.0"?>
<project>
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <properties>
        <lib.version>5.0.0</lib.version>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.managed</groupId>
                <artifactId>lib</artifactId>
                <version>${lib.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>`

	r := newTestResolver(map[string]string{
		"https://repo.test/com/parent/parent/1.0.0/parent-1.0.0.pom": parentPOM,
	})

	child := &POM{
		ArtifactID: "child",
		Version:    "2.0.0",
		Parent: &Parent{
			GroupID:    "com.parent",
			ArtifactID: "parent",
			Version:    "1.0.0",
		},
		Dependencies: []Dependency{
			{GroupID: "com.managed", ArtifactID: "lib", Version: "${lib.version}"},
		},
	}

	effective, err := r.ResolveEffectivePOM(child)
	require.NoError(t, err)

	// GroupID inherited from parent
	require.Equal(t, "com.parent", effective.GroupID)

	// Property inherited and interpolated
	require.Equal(t, "5.0.0", effective.Dependencies[0].Version)

	// DependencyManagement inherited
	require.NotNil(t, effective.DependencyManagement)
	require.Len(t, effective.DependencyManagement.Dependencies, 1)
}

func TestResolveBOMImports(t *testing.T) {
	t.Parallel()
	bomPOM := `<?xml version="1.0"?>
<project>
    <groupId>com.bom</groupId>
    <artifactId>bom</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.managed</groupId>
                <artifactId>from-bom</artifactId>
                <version>3.0.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>`

	r := newTestResolver(map[string]string{
		"https://repo.test/com/bom/bom/1.0.0/bom-1.0.0.pom": bomPOM,
	})

	pom := &POM{
		GroupID:    "com.test",
		ArtifactID: "app",
		Version:    "1.0.0",
		DependencyManagement: &DependencyManagement{
			Dependencies: []Dependency{
				// BOM import
				{GroupID: "com.bom", ArtifactID: "bom", Version: "1.0.0", Scope: "import", Type: "pom"},
				// Own managed dep
				{GroupID: "com.own", ArtifactID: "lib", Version: "2.0.0"},
			},
		},
	}

	err := r.resolveBOMImports(pom, 0)
	require.NoError(t, err)

	// BOM import entry should be removed, replaced by its contents
	keys := make(map[string]string)
	for _, d := range pom.DependencyManagement.Dependencies {
		keys[d.Key()] = d.Version
	}

	require.Equal(t, "2.0.0", keys["com.own:lib"])
	require.Equal(t, "3.0.0", keys["com.managed:from-bom"])
	// BOM import itself should not remain
	require.NotContains(t, keys, "com.bom:bom")
}

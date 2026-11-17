// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// failingAgentImpl returns 404 for all requests instantly (no retries needed).
type failingAgentImpl struct{}

func (f *failingAgentImpl) SendGetRequest(_ context.Context, _ *http.Client, url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("")),
	}, fmt.Errorf("not found: %s", url)
}

func (f *failingAgentImpl) SendPostRequest(_ context.Context, _ *http.Client, _ string, _ []byte, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *failingAgentImpl) SendHeadRequest(_ context.Context, _ *http.Client, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

// transientFailAgentImpl simulates a transient network failure (no HTTP
// response) for all requests, as opposed to a definitive 404.
type transientFailAgentImpl struct{}

func (f *transientFailAgentImpl) SendGetRequest(_ context.Context, _ *http.Client, url string) (*http.Response, error) {
	return nil, fmt.Errorf("connection refused: %s", url)
}

func (f *transientFailAgentImpl) SendPostRequest(_ context.Context, _ *http.Client, _ string, _ []byte, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *transientFailAgentImpl) SendHeadRequest(_ context.Context, _ *http.Client, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestDecomposerDefaultOptions(t *testing.T) {
	t.Parallel()
	d := New()
	opts := d.DefaultOptions()
	require.IsType(t, Options{}, opts)

	o, ok := opts.(Options)
	require.True(t, ok)
	require.Equal(t, defaultRepoURL, o.RepoURL)
	require.Equal(t, defaultConcurrency, o.Concurrency)
}

func TestDecomposerRequirements(t *testing.T) {
	t.Parallel()
	d := New()
	require.Nil(t, d.Requirements(nil))
}

func TestDecomposerExtractSimple(t *testing.T) {
	t.Parallel()

	// Parse and extract with a resolver that fails all remote fetches.
	// This tests that local pom.xml parsing and tree building works
	// even when remote resolution isn't available.
	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	resolver := NewResolver(&Options{RepoURL: "https://unused.test", Concurrency: 1})
	resolver.Agent = resolver.Agent.WithRetries(0)
	resolver.Agent.SetImplementation(&failingAgentImpl{})

	effective, err := resolver.ResolveEffectivePOM(pom)
	require.NoError(t, err)

	dt := NewDependencyTree(effective, resolver, &defaultOptions)
	err = dt.Build()
	require.NoError(t, err)

	opts := &api.DecomposerOptions{WorkDir: "testdata/simple"}
	nl, err := dt.ToNodeList(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Should have the root node at minimum
	require.Len(t, nl.GetRootElements(), 1)

	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.Equal(t, "simple-app", root.GetName())
	require.Equal(t, "pkg:maven/com.example/simple-app@1.0.0", root.GetIdentifiers()[int32(1)])

	// Direct compile deps should be resolved (guava, commons-lang3)
	// Test and provided deps should be excluded by default
	nodes := nl.GetNodes()
	require.GreaterOrEqual(t, len(nodes), 3) // root + guava + commons-lang3
}

// TestDecomposerExtractNetworkingDisabled verifies that with no network to
// read other POMs from, the graph still holds what pom.xml declares itself:
// its direct dependencies, at the versions its own properties give them.
func TestDecomposerExtractNetworkingDisabled(t *testing.T) {
	t.Parallel()

	nl, err := New().Extract(&api.DecomposerOptions{
		WorkDir:    "testdata/simple",
		Networking: api.NetworkDisabled,
	})
	require.NoError(t, err)

	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.Equal(t, "simple-app", root.GetName())

	purls := []string{}
	for _, n := range nl.GetNodes() {
		if n.GetId() != root.GetId() {
			purls = append(purls, n.GetIdentifiers()[int32(1)])
		}
	}
	// The test and provided dependencies stay out, as with the network.
	require.ElementsMatch(t, []string{
		"pkg:maven/com.google.guava/guava@33.0.0-jre",
		"pkg:maven/org.apache.commons/commons-lang3@3.14.0",
	}, purls)

	require.Len(t, nl.GetEdges(), 1)
	require.Equal(t, root.GetId(), nl.GetEdges()[0].GetFrom())
	require.Len(t, nl.GetEdges()[0].GetTo(), 2)
}

// writeMultiModule lays out a multi-module project in a temp dir: a root
// POM that is the parent of a parent kept in a directory of its own, which
// a module names by relativePath. Neither parent is in any repository. It
// returns the module's directory.
func writeMultiModule(t *testing.T, moduleParent string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}

	write("pom.xml", `<?xml version="1.0"?>
<project>
    <groupId>com.example</groupId>
    <artifactId>reactor</artifactId>
    <version>2.0.0</version>
    <packaging>pom</packaging>
    <properties><managed.version>3.1.0</managed.version></properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.dep</groupId>
                <artifactId>managed</artifactId>
                <version>${managed.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>`)
	write("build/parent/pom.xml", `<?xml version="1.0"?>
<project>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>reactor</artifactId>
        <version>2.0.0</version>
        <relativePath>../../pom.xml</relativePath>
    </parent>
    <artifactId>module-parent</artifactId>
    <packaging>pom</packaging>
    <dependencies>
        <dependency>
            <groupId>com.dep</groupId>
            <artifactId>inherited</artifactId>
            <version>1.5.0</version>
        </dependency>
    </dependencies>
</project>`)
	write("module/pom.xml", `<?xml version="1.0"?>
<project>
    `+moduleParent+`
    <artifactId>module</artifactId>
    <dependencies>
        <dependency>
            <groupId>com.dep</groupId>
            <artifactId>managed</artifactId>
        </dependency>
    </dependencies>
</project>`)
	return filepath.Join(root, "module")
}

// TestDecomposerExtractLocalParent verifies that a module's parent is read
// from the source tree, where a multi-module project keeps it, and that
// parent's own parent from there in turn: the module gets the version its
// reactor manages and the dependency its parent declares, with or without
// a repository to ask.
func TestDecomposerExtractLocalParent(t *testing.T) {
	t.Parallel()

	const parentRef = `<parent>
        <groupId>com.example</groupId>
        <artifactId>module-parent</artifactId>
        <version>2.0.0</version>
        <relativePath>../build/parent</relativePath>
    </parent>`

	purls := func(t *testing.T, nl *sbom.NodeList) []string {
		t.Helper()
		// Without the qualifier naming the repository, which a resolver
		// pointed at a repository of its own adds.
		out := make([]string, 0, len(nl.GetNodes()))
		for _, n := range nl.GetNodes() {
			purl, _, _ := strings.Cut(n.GetIdentifiers()[int32(1)], "?")
			out = append(out, purl)
		}
		return out
	}
	want := []string{
		"pkg:maven/com.example/module@2.0.0",
		"pkg:maven/com.dep/managed@3.1.0",
		"pkg:maven/com.dep/inherited@1.5.0",
	}

	t.Run("without a repository", func(t *testing.T) {
		t.Parallel()
		nl, err := New().Extract(&api.DecomposerOptions{
			WorkDir:    writeMultiModule(t, parentRef),
			Networking: api.NetworkDisabled,
		})
		require.NoError(t, err)
		require.ElementsMatch(t, want, purls(t, nl))
	})

	t.Run("with a repository that has neither parent", func(t *testing.T) {
		t.Parallel()
		dir := writeMultiModule(t, parentRef)
		pom, err := ParsePomXML(dir)
		require.NoError(t, err)

		resolver := NewResolver(&Options{RepoURL: "https://unused.test", Concurrency: 1})
		resolver.Agent = resolver.Agent.WithRetries(0)
		resolver.Agent.SetImplementation(&failingAgentImpl{})

		effective, err := resolver.ResolveEffectivePOMIn(pom, dir)
		require.NoError(t, err)
		dt := NewDependencyTree(effective, resolver, &defaultOptions)
		require.NoError(t, dt.Build())
		nl, err := dt.ToNodeList(nil)
		require.NoError(t, err)
		require.ElementsMatch(t, want, purls(t, nl))
	})

	// What is at the path is the parent only when it is the artifact the
	// module names, and a relativePath stated empty says not to look.
	for name, ref := range map[string]string{
		"another artifact at the path": `<parent>
        <groupId>com.example</groupId>
        <artifactId>some-other-parent</artifactId>
        <version>2.0.0</version>
        <relativePath>../build/parent</relativePath>
    </parent>`,
		"another version at the path": `<parent>
        <groupId>com.example</groupId>
        <artifactId>module-parent</artifactId>
        <version>9.9.9</version>
        <relativePath>../build/parent</relativePath>
    </parent>`,
		"an empty relativePath": `<parent>
        <groupId>com.example</groupId>
        <artifactId>module-parent</artifactId>
        <version>2.0.0</version>
        <relativePath/>
    </parent>`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nl, err := New().Extract(&api.DecomposerOptions{
				WorkDir:    writeMultiModule(t, ref),
				Networking: api.NetworkDisabled,
			})
			require.NoError(t, err)
			for _, p := range purls(t, nl) {
				require.NotContains(t, p, "inherited", "the local POM was merged though it is not the parent")
			}
		})
	}
}

// TestDecomposerExtractTransientFails verifies that a transient fetch failure
// (after retries) fails the extraction rather than silently producing an
// incomplete tree. This is the counterpart to TestDecomposerExtractSimple,
// where a definitive 404 is tolerated.
func TestDecomposerExtractTransientFails(t *testing.T) {
	t.Parallel()

	pom, err := ParsePomXML("testdata/simple")
	require.NoError(t, err)

	resolver := NewResolver(&Options{RepoURL: "https://unused.test", Concurrency: 1})
	resolver.Agent = resolver.Agent.WithRetries(0)
	resolver.Agent.SetImplementation(&transientFailAgentImpl{})

	effective, err := resolver.ResolveEffectivePOM(pom)
	require.NoError(t, err)

	dt := NewDependencyTree(effective, resolver, &defaultOptions)
	err = dt.Build()
	require.Error(t, err, "transient fetch failure should fail the build")
}

func TestCanDecompose(t *testing.T) {
	t.Parallel()
	require.True(t, CanDecompose("testdata/simple"))
	require.False(t, CanDecompose("testdata/nonexistent"))
}

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

	api "github.com/carabiner-dev/unpack/api/v1"
)

// failingAgentImpl returns 404 for all requests instantly (no retries needed).
type failingAgentImpl struct{}

func (f *failingAgentImpl) SendGetRequest(_ *http.Client, url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("")),
	}, fmt.Errorf("not found: %s", url)
}

func (f *failingAgentImpl) SendPostRequest(_ *http.Client, _ string, _ []byte, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *failingAgentImpl) SendHeadRequest(_ *http.Client, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

// transientFailAgentImpl simulates a transient network failure (no HTTP
// response) for all requests, as opposed to a definitive 404.
type transientFailAgentImpl struct{}

func (f *transientFailAgentImpl) SendGetRequest(_ *http.Client, url string) (*http.Response, error) {
	return nil, fmt.Errorf("connection refused: %s", url)
}

func (f *transientFailAgentImpl) SendPostRequest(_ *http.Client, _ string, _ []byte, _ string) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *transientFailAgentImpl) SendHeadRequest(_ *http.Client, _ string) (*http.Response, error) {
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

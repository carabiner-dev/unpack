// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/stretchr/testify/require"
)

// TestMissingPOMsAreReported checks a dependency whose POM the repository
// does not have keeps its place in the tree and is reported, as is an
// artifact the repository has no checksums for.
func TestMissingPOMsAreReported(t *testing.T) {
	t.Parallel()

	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/com/test/present/1.0.0/present-1.0.0.pom":
			//nolint:errcheck // a fake server's writes have nowhere to fail
			fmt.Fprint(w, `<?xml version="1.0"?>
<project>
    <groupId>com.test</groupId>
    <artifactId>present</artifactId>
    <version>1.0.0</version>
</project>`)
		case "/com/test/present/1.0.0/present-1.0.0.jar.sha1":
			fmt.Fprint(w, "da39a3ee5e6b4b0d3255bfef95601890afd80709") //nolint:errcheck // a fake server's writes have nowhere to fail
		default:
			http.NotFound(w, r)
		}
	}))
	defer repo.Close()

	resolver := NewResolver(&Options{RepoURL: repo.URL, Concurrency: 1})
	resolver.Agent = resolver.Agent.WithRetries(0)

	root := &POM{
		GroupID: "com.example", ArtifactID: "app", Version: "1.0.0",
		Dependencies: []Dependency{
			{GroupID: "com.test", ArtifactID: "present", Version: "1.0.0"},
			{GroupID: "com.test", ArtifactID: "absent", Version: "2.0.0"},
		},
	}

	var out bytes.Buffer
	dt := NewDependencyTree(root, resolver, &defaultOptions)
	dt.log = clog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	require.NoError(t, dt.Build())
	dt.reportSkipped()

	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "POMs were not found")
	require.Contains(t, logged, "failed=1")
	require.Contains(t, logged, "requested=2")
	require.Contains(t, logged, "[com.test:absent:2.0.0]")
	// The dependency is still in the tree.
	require.Contains(t, dt.resolved, "com.test:absent")

	out.Reset()
	dt.FetchHashes(false)
	logged = out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "no checksums")
	require.Contains(t, logged, "failed=1")
	require.Contains(t, logged, "[com.test:absent:2.0.0]")

	// A tree nobody gave a logger says nothing and builds the same.
	quiet := NewDependencyTree(root, resolver, &defaultOptions)
	require.NoError(t, quiet.Build())
	quiet.reportSkipped()
}

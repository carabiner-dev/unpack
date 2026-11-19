// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func loggedContext(t *testing.T, out *bytes.Buffer) context.Context {
	t.Helper()
	logger := clog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return clog.WithLogger(t.Context(), logger)
}

// TestUnreadableGoModIsReported checks a module whose go.mod cannot be
// read is reported: as a warning when the proxy was asked, and at the
// debug level when networking was off and the module cache was all there
// was to read.
func TestUnreadableGoModIsReported(t *testing.T) {
	// The module cache must not answer for the modules.
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOFLAGS", "-modcacherw")

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/example.com/readable/") {
			fmt.Fprint(w, "module example.com/readable\n") //nolint:errcheck // a fake server's writes have nowhere to fail
			return
		}
		http.NotFound(w, r)
	}))
	defer proxy.Close()

	set := &ModuleSet{
		Main: Module{Path: "example.com/app"},
		Requires: []Module{
			{Path: "example.com/readable", Version: "v1.0.0"},
			{Path: "example.com/unreadable", Version: "v1.0.0"},
		},
	}
	set.Modules = append(set.Modules, set.Requires...)
	d := Decomposer{}
	opts := &Options{ProxyURL: proxy.URL, HTTPClient: proxy.Client()}

	var out bytes.Buffer
	d.resolveGraph(loggedContext(t, &out), set, opts, api.NetworkEssential)
	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "failed=1")
	require.Contains(t, logged, "requested=2")
	require.Contains(t, logged, "example.com/unreadable@v1.0.0")
	require.NotContains(t, logged, "[example.com/readable")

	// Offline, both are missing from the cache, and that is no warning.
	out.Reset()
	d.resolveGraph(loggedContext(t, &out), set, opts, api.NetworkDisabled)
	require.NotContains(t, out.String(), "level=WARN")
	require.Contains(t, out.String(), "failed=2")
}

// TestDepsDevFailuresAreReported checks a module deps.dev does not answer
// for is reported, and one it answers for with no license is not.
func TestDepsDevFailuresAreReported(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.EscapedPath(), "unlicensed"):
			fmt.Fprint(w, `{"licenses": []}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		case strings.Contains(r.URL.EscapedPath(), "licensed"):
			fmt.Fprint(w, `{"licenses": ["MIT"]}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	lc := newLicenseClient("", 2)
	lc.agent = lc.agent.WithRetries(0)
	lc.depsDevURL = server.URL
	lc.log = clog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	got := lc.FetchLicenses([]modKey{
		{Path: "example.com/licensed", Version: "v1.0.0"},
		{Path: "example.com/unlicensed", Version: "v1.0.0"},
		{Path: "example.com/unknown", Version: "v1.0.0"},
	}, false)
	require.Len(t, got, 1)

	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "failed=1")
	require.Contains(t, logged, "requested=3")
	require.Contains(t, logged, "[example.com/unknown@v1.0.0]")
}

// TestUnhashedModulesAreReported checks the modules the proxy states no
// zip hash for are reported.
func TestUnhashedModulesAreReported(t *testing.T) {
	t.Parallel()

	nl := sbom.NewNodeList()
	nl.AddNode(&sbom.Node{Id: "dep", Name: "example.invalid/dep", Version: "v1.2.3"})

	// The public proxy is the only one asked, so it is stood in for by a
	// client that fails every request.
	var out bytes.Buffer
	d := Decomposer{}
	d.hashModuleZips(loggedContext(t, &out), nl, "example.com/app", &Options{
		HTTPClient: &http.Client{Transport: failingTransport{}},
	})

	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "failed=1")
	require.Contains(t, logged, "[example.invalid/dep@v1.2.3]")
}

// failingTransport fails every request without touching the network.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("no network in this test")
}

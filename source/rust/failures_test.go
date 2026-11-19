// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

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

// TestCratesIOFailuresAreReported checks lookups that fail are skipped and
// the caller's logger told once, as a warning, and that a clean run and a
// client with no logger say nothing.
func TestCratesIOFailuresAreReported(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/fine/"):
			fmt.Fprint(w, `{"version":{"license":"MIT"}}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		case strings.Contains(r.URL.Path, "/garbled/"):
			fmt.Fprint(w, `not json`) //nolint:errcheck // a fake server's writes have nowhere to fail
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	client := NewCratesIOClient(2)
	client.BaseURL = server.URL
	client.RequestInterval = 0
	client.Agent = client.Agent.WithRetries(0)
	client.Logger = clog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	fine := PackageKey{Name: "fine", Version: "1.0.0"}
	got := client.FetchAll([]PackageKey{fine, {Name: "missing", Version: "2.0.0"}, {Name: "garbled", Version: "1.0.0"}})
	require.Len(t, got, 1)
	require.Contains(t, got, fine)

	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "failed=2")
	require.Contains(t, logged, "requested=3")
	require.Contains(t, logged, "garbled@1.0.0 missing@2.0.0")

	out.Reset()
	client.FetchAll([]PackageKey{fine})
	require.Empty(t, out.String())

	quiet := NewCratesIOClient(2)
	quiet.BaseURL = server.URL
	quiet.RequestInterval = 0
	quiet.Agent = quiet.Agent.WithRetries(0)
	require.Empty(t, quiet.FetchAll([]PackageKey{{Name: "missing", Version: "2.0.0"}}))
}

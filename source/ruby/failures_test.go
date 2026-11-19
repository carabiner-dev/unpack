// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

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

// TestRubyGemsFailuresAreReported checks lookups that fail are skipped and
// the caller's logger told once, and that a clean run and a client with no
// logger say nothing.
func TestRubyGemsFailuresAreReported(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fine/versions/1.0.0.json":
			fmt.Fprint(w, `{"licenses": ["MIT"]}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		case "/garbled/versions/1.0.0.json":
			fmt.Fprint(w, `not json`) //nolint:errcheck // a fake server's writes have nowhere to fail
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	client := NewRubyGemsClient(2)
	client.BaseURL = server.URL
	client.Logger = clog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	fine := &GemSpec{Name: "fine", Version: "1.0.0"}
	got := client.FetchAll([]*GemSpec{fine, {Name: "missing", Version: "2.0.0"}, {Name: "garbled", Version: "1.0.0"}})
	require.Len(t, got, 1)
	require.Contains(t, got, fine)

	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "failed=2")
	require.Contains(t, logged, "requested=3")
	require.Contains(t, logged, "garbled@1.0.0 missing@2.0.0")

	out.Reset()
	client.FetchAll([]*GemSpec{fine})
	require.Empty(t, out.String())

	quiet := NewRubyGemsClient(2)
	quiet.BaseURL = server.URL
	require.Empty(t, quiet.FetchAll([]*GemSpec{{Name: "missing", Version: "2.0.0"}}))
}

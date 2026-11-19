// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/stretchr/testify/require"
)

// uncomparable is a handler held by value with a field that cannot be
// compared, as a program's own handler may be.
type uncomparable struct {
	slog.Handler
	_ []string
}

// TestSilentUnlessWired checks the library's logger prints nothing for a
// context nothing was wired into, and that it does not reach the program's
// default logger to do so.
func TestSilentUnlessWired(t *testing.T) { //nolint:paralleltest // replaces slog's default logger
	var global bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&global, nil)))
	defer slog.SetDefault(previous)

	FromContext(t.Context()).Warn("nobody asked")
	FromContext(nil).Warn("nor here") //nolint:staticcheck // a nil context is what is being tested
	require.False(t, FromContext(t.Context()).Enabled(t.Context(), slog.LevelError))
	require.Empty(t, global.String())

	// A context that carries other things is still not wired.
	type key struct{}
	FromContext(context.WithValue(t.Context(), key{}, "value")).Error("still nobody")
	require.Empty(t, global.String())
}

// TestWiredLogger checks a logger the caller wired is the one used, at the
// level the caller set.
func TestWiredLogger(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	handler := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn})
	ctx := clog.WithLogger(t.Context(), clog.New(handler))

	logger := FromContext(ctx)
	logger.Debug("too quiet to show")
	logger.Warnf("lookup failed for %s", "left-pad")
	require.NotContains(t, out.String(), "too quiet")
	require.Contains(t, out.String(), "lookup failed for left-pad")

	// A context derived from it keeps it.
	type key struct{}
	out.Reset()
	FromContext(context.WithValue(ctx, key{}, "value")).Warn("derived")
	require.Contains(t, out.String(), "derived")
}

// TestWiredUncomparableHandler checks a handler that cannot be compared is
// taken for what it is, a wired one, and does not panic.
func TestWiredUncomparableHandler(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	handler := uncomparable{Handler: slog.NewTextHandler(&out, nil)}
	ctx := clog.WithLogger(t.Context(), clog.New(handler))

	FromContext(ctx).Warn("through the odd handler")
	require.Contains(t, out.String(), "through the odd handler")
}

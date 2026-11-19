// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/unpack/internal/logging"
)

func TestSlogLevel(t *testing.T) {
	t.Parallel()
	for name, expected := range map[string]slog.Level{
		"trace":   slog.LevelDebug,
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"fatal":   slog.LevelError,
		"panic":   slog.LevelError,
	} {
		level, err := slogLevel(name)
		require.NoError(t, err, name)
		require.Equal(t, expected, level, name)
	}

	_, err := slogLevel("chatty")
	require.Error(t, err)
}

// TestInitLoggingWiresContext checks the command's context carries a
// logger the library finds, writing to the command's standard error at the
// level --log-level names.
func TestInitLoggingWiresContext(t *testing.T) { //nolint:paralleltest // sets the package's command line options
	previous := commandLineOpts.logLevel
	defer func() { commandLineOpts.logLevel = previous }()

	for _, tc := range []struct {
		level     string
		showsWarn bool
		showsDbg  bool
	}{
		{"debug", true, true},
		{"info", true, false},
		{"error", false, false},
	} {
		commandLineOpts.logLevel = tc.level

		var stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		require.NoError(t, initLogging(cmd, nil))

		logger := logging.FromContext(cmd.Context())
		logger.Warn("a lookup failed")
		logger.Debug("a detail")

		require.Equal(t, tc.showsWarn, bytes.Contains(stderr.Bytes(), []byte("a lookup failed")), tc.level)
		require.Equal(t, tc.showsDbg, bytes.Contains(stderr.Bytes(), []byte("a detail")), tc.level)
	}

	commandLineOpts.logLevel = "chatty"
	require.Error(t, initLogging(&cobra.Command{}, nil))
}

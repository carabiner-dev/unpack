// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/stretchr/testify/require"
)

func debugLogger(out *bytes.Buffer) *clog.Logger {
	return clog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestFailuresReport(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	log := debugLogger(&out)

	// Nothing failed, nothing said.
	none := &Failures{}
	none.Report(log, 10, "lookups failed", "items that failed")
	require.Empty(t, out.String())

	failures := &Failures{}
	failures.Add("zeta@1.0", errors.New("refused"))
	failures.Add("alpha@2.0", errors.New("timed out"))
	require.Equal(t, 2, failures.Len())
	failures.Report(log, 5, "lookups failed", "items that failed")

	logged := out.String()
	require.Equal(t, 1, strings.Count(logged, "level=WARN"), logged)
	require.Contains(t, logged, "failed=2")
	require.Contains(t, logged, "requested=5")
	require.Contains(t, logged, "first_error=refused")
	// The items are at the debug level, sorted.
	require.Contains(t, logged, `level=DEBUG msg="items that failed" items="[alpha@2.0 zeta@1.0]"`)

	// With no reason given there is no error to state.
	out.Reset()
	unexplained := &Failures{}
	unexplained.Add("beta@1.0", nil)
	unexplained.Report(log, 1, "lookups failed", "items that failed")
	require.NotContains(t, out.String(), "first_error")

	// Quietly, the summary is not a warning.
	out.Reset()
	failures.ReportQuietly(log, 5, "lookups not made", "items not looked up")
	require.NotContains(t, out.String(), "level=WARN")
	require.Equal(t, 2, strings.Count(out.String(), "level=DEBUG"))

	// A silent logger takes it all without a word or a panic.
	failures.Report(Silent(), 5, "lookups failed", "items that failed")
}

func TestFailuresConcurrentAdd(t *testing.T) {
	t.Parallel()
	failures := &Failures{}
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { failures.Add("item", errors.New("failed")) })
	}
	wg.Wait()
	require.Equal(t, 50, failures.Len())
}

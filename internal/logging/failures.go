// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"slices"
	"sync"

	"github.com/chainguard-dev/clog"
)

// Failures collects the lookups a run skipped because they failed, to
// report them once.
//
// A lookup that fails does not fail an extraction: the graph is built
// from what is at hand and the rest is left out. Left out in silence,
// though, the gap has nothing to explain it, so the caller is told. One
// message a lookup would bury everything else when a registry is down,
// which is when most of them fail at once.
//
// The zero value is ready to use, and safe to add to from several
// goroutines.
type Failures struct {
	mu    sync.Mutex
	items []string
	first error
}

// Add records that the lookup of an item failed, and why. A nil error is
// for an item that came back with nothing and no reason given.
func (f *Failures) Add(item string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = append(f.items, item)
	if f.first == nil {
		f.first = err
	}
}

// Len returns how many lookups failed.
func (f *Failures) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.items)
}

// Report tells the logger of the failures, and nothing when there were
// none: a warning with how many failed of how many were requested and the
// first error, and the items themselves at the debug level.
func (f *Failures) Report(log *clog.Logger, requested int, warning, detail string) {
	f.reportAt(log.Warn, log, requested, warning, detail)
}

// ReportQuietly is Report with the summary at the debug level too, for
// failures the caller asked for: lookups that could not be made because
// networking was turned off.
func (f *Failures) ReportQuietly(log *clog.Logger, requested int, summary, detail string) {
	f.reportAt(log.Debug, log, requested, summary, detail)
}

func (f *Failures) reportAt(summarize func(string, ...any), log *clog.Logger, requested int, summary, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.items) == 0 {
		return
	}
	args := []any{"failed", len(f.items), "requested", requested}
	if f.first != nil {
		args = append(args, "first_error", f.first)
	}
	summarize(summary, args...)

	items := slices.Clone(f.items)
	slices.Sort(items)
	log.Debug(detail, "items", items)
}

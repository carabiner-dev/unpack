// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package logging is how the library logs: through the logger its caller
// put in the context, and not at all when the caller put none.
//
// The logger is a clog one. A program wires it the way clog has it,
//
//	ctx = clog.WithLogger(ctx, clog.New(handler))
//
// and passes that context to an unpacker, which hands it on to its
// decomposers in their options. The library never logs to a global logger:
// what a program prints is the program's to decide.
package logging

import (
	"context"
	"log/slog"

	"github.com/chainguard-dev/clog"
)

// silent is the logger of a context nothing was wired into.
var silent = clog.New(slog.DiscardHandler)

// Silent returns a logger that discards everything, for code run with no
// context to read one from.
func Silent() *clog.Logger { return silent }

// FromContext returns the logger the caller wired into the context, and
// one that discards everything when there is none.
//
// clog itself falls back to the program's default slog logger, which
// prints. That is right for a program and wrong for a library, whose
// warnings would turn up on the standard error of whatever uses it.
func FromContext(ctx context.Context) *clog.Logger {
	if ctx == nil || !wired(ctx) {
		return silent
	}
	return clog.FromContext(ctx)
}

// wired says whether the context carries a logger.
//
// clog does not say: it keeps the logger under a key of its own and
// answers for a context without one with a logger over slog's default
// handler. So that is what is looked for. A logger wired over that very
// handler reads as none, and a program that wants the library's logs on
// slog's default wires one over a handler of its own making.
func wired(ctx context.Context) (is bool) {
	// Handlers are compared as interfaces, which panics when they hold a
	// type that cannot be compared. The default one can be, so a handler
	// that cannot is not it.
	defer func() {
		if recover() != nil {
			is = true
		}
	}()
	return clog.FromContext(ctx).Handler() != slog.Handler(clog.NewHandler(slog.Default().Handler()))
}

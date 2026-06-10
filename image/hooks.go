// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import "io"

// PullHooks receives notifications while image blobs are downloaded. All
// callbacks are optional; nil hooks (or nil callbacks) are skipped. A text
// UI can register these to render download progress.
//
// Callbacks may be invoked from concurrent goroutines (layers download in
// parallel) so implementations must be safe for concurrent use.
type PullHooks struct {
	// LayerStart fires when a layer blob starts downloading. total is the
	// compressed size in bytes, or -1 when unknown.
	LayerStart func(digest string, total int64)

	// LayerProgress fires as layer bytes arrive.
	LayerProgress func(digest string, complete, total int64)

	// LayerDone fires when a layer blob has been fully downloaded.
	LayerDone func(digest string)
}

func (h *PullHooks) layerStart(digest string, total int64) {
	if h != nil && h.LayerStart != nil {
		h.LayerStart(digest, total)
	}
}

func (h *PullHooks) layerProgress(digest string, complete, total int64) {
	if h != nil && h.LayerProgress != nil {
		h.LayerProgress(digest, complete, total)
	}
}

func (h *PullHooks) layerDone(digest string) {
	if h != nil && h.LayerDone != nil {
		h.LayerDone(digest)
	}
}

// progressWriter counts bytes written through it and reports them to the
// pull hooks.
type progressWriter struct {
	w        io.Writer
	hooks    *PullHooks
	digest   string
	total    int64
	complete int64
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.complete += int64(n)
	p.hooks.layerProgress(p.digest, p.complete, p.total)
	return n, err
}

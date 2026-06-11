// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Whiteout markers per the OCI image-spec layer specification.
const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
)

// flatten squashes the image layers into a single tar stream written to w,
// applying whiteouts the way a container runtime would when stacking the
// layers.
//
// The algorithm walks the layers top-down (adapted from go-containerregistry's
// mutate.Extract): a path seen in a higher layer shadows the same path below,
// a ".wh.<name>" tombstone hides <name> in lower layers, and a
// ".wh..wh..opq" marker hides the whole directory's lower-layer contents.
// Opaque markers take effect only after their own layer finishes, since they
// apply to lower layers, not to siblings in the same one. mutate.Extract
// itself does not implement opaque directories, which is why we carry our
// own copy of the loop.
func flatten(layers []v1.Layer, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close() //nolint:errcheck // flushed explicitly below

	// shadowed[p] records that p exists in a processed (higher) layer; a
	// true value also hides everything beneath p (tombstones and files do,
	// directories don't).
	shadowed := map[string]bool{}

	for i := len(layers) - 1; i >= 0; i-- {
		opaques, err := flattenLayer(tw, shadowed, layers[i])
		if err != nil {
			return fmt.Errorf("flattening layer %d: %w", i, err)
		}
		for _, dir := range opaques {
			shadowed[dir] = true
		}
	}
	return tw.Flush()
}

// flattenLayer copies one layer's surviving entries into tw and returns the
// directories its opaque markers hide in lower layers.
func flattenLayer(tw *tar.Writer, shadowed map[string]bool, layer v1.Layer) (opaques []string, err error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("opening layer: %w", err)
	}
	defer rc.Close() //nolint:errcheck // read-only stream

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading layer tar: %w", err)
		}

		name := path.Clean(strings.TrimPrefix(hdr.Name, "/"))
		base := path.Base(name)
		dir := path.Dir(name)

		if base == opaqueMarker {
			opaques = append(opaques, dir)
			continue
		}

		tombstone := strings.HasPrefix(base, whiteoutPrefix)
		if tombstone {
			name = path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))
		}

		// Shadowed by an entry or tombstone in a higher layer?
		if _, ok := shadowed[name]; ok && !tombstone {
			continue
		}
		if underShadow(shadowed, name) {
			continue
		}

		// Tombstones and non-directories hide lower-layer children too.
		shadowed[name] = tombstone || hdr.Typeflag != tar.TypeDir
		if tombstone {
			continue
		}

		hdr.Name = name
		// PAX lifts the USTAR 100-char name limit and keeps the output
		// format independent of the input layers'.
		hdr.Format = tar.FormatPAX
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("writing entry %q: %w", name, err)
		}
		if hdr.Size > 0 {
			if _, err := io.CopyN(tw, tr, hdr.Size); err != nil {
				return nil, fmt.Errorf("copying entry %q: %w", name, err)
			}
		}
	}
	return opaques, nil
}

// underShadow reports whether any ancestor of name is recorded as hiding
// its children.
func underShadow(shadowed map[string]bool, name string) bool {
	for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if shadowed[dir] {
			return true
		}
	}
	return false
}

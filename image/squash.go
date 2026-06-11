// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/sync/errgroup"
)

// squashToFS downloads the image's layers, flattens them into a single
// filesystem (applying whiteouts the way the container runtime would) and
// returns it as a lazily-read fs.FS. The returned cleanup function releases
// the temporary backing file and must be called when the filesystem is no
// longer needed.
//
// Layer blobs download in parallel; hooks (optional) receive per-layer
// progress as the bytes arrive.
func squashToFS(ctx context.Context, img v1.Image, hooks *PullHooks) (fsys fs.FS, cleanup func() error, err error) {
	tmpDir, err := os.MkdirTemp("", "unpack-oci-")
	if err != nil {
		return nil, nil, fmt.Errorf("creating staging dir: %w", err)
	}
	cleanup = func() error { return os.RemoveAll(tmpDir) }
	defer func() {
		if err != nil {
			//nolint:errcheck,gosec // best-effort cleanup; the original error is surfaced
			cleanup()
		}
	}()

	local, paths, err := fetchLayers(ctx, img, tmpDir, hooks)
	if err != nil {
		return nil, cleanup, err
	}

	// Flatten the local layers into a single tar, applying whiteouts and
	// opaque directories.
	squashed := filepath.Join(tmpDir, "squashed.tar")
	if err := writeSquashed(local, squashed); err != nil {
		return nil, cleanup, err
	}

	// The compressed layer blobs are no longer needed once flattened.
	for _, p := range paths {
		//nolint:errcheck,gosec // best-effort space reclaim inside our own tmpdir
		os.Remove(p)
	}

	f, err := os.Open(squashed)
	if err != nil {
		return nil, cleanup, fmt.Errorf("opening squashed filesystem: %w", err)
	}
	prev := cleanup
	cleanup = func() error {
		//nolint:errcheck,gosec // close before removing; removal is the part that matters
		f.Close()
		return prev()
	}

	tfs, err := newTarFS(f, f)
	if err != nil {
		return nil, cleanup, fmt.Errorf("indexing squashed filesystem: %w", err)
	}
	return tfs, cleanup, nil
}

// fetchLayers downloads all layer blobs of img concurrently into dir and
// returns equivalent layers backed by the local files, plus the staged
// paths so callers can reclaim the space.
func fetchLayers(ctx context.Context, img v1.Image, dir string, hooks *PullHooks) ([]v1.Layer, []string, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, nil, fmt.Errorf("reading image layers: %w", err)
	}

	paths := make([]string, len(layers))
	g, ctx := errgroup.WithContext(ctx)
	for i, layer := range layers {
		g.Go(func() error {
			p, err := fetchLayer(ctx, layer, dir, hooks)
			if err != nil {
				return err
			}
			paths[i] = p
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}

	local := make([]v1.Layer, len(paths))
	for i, p := range paths {
		l, err := tarball.LayerFromFile(p)
		if err != nil {
			return nil, nil, fmt.Errorf("opening staged layer %q: %w", p, err)
		}
		local[i] = l
	}
	return local, paths, nil
}

// fetchLayer streams one layer blob to a file in dir, reporting progress to
// the hooks, and returns the staged path.
func fetchLayer(ctx context.Context, layer v1.Layer, dir string, hooks *PullHooks) (string, error) {
	digest, err := layer.Digest()
	if err != nil {
		return "", fmt.Errorf("reading layer digest: %w", err)
	}
	size, err := layer.Size()
	if err != nil {
		size = -1
	}

	rc, err := layer.Compressed()
	if err != nil {
		return "", fmt.Errorf("fetching layer %s: %w", digest, err)
	}
	defer rc.Close() //nolint:errcheck // read-only stream

	dst := filepath.Join(dir, digest.Hex+".tar.gz")
	f, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("staging layer %s: %w", digest, err)
	}

	hooks.layerStart(digest.String(), size)
	pw := &progressWriter{w: f, hooks: hooks, digest: digest.String(), total: size}
	err = copyWithContext(ctx, pw, rc)
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("downloading layer %s: %w", digest, err)
	}
	hooks.layerDone(digest.String())
	return dst, nil
}

// writeSquashed streams the flattened filesystem of the local layers into a
// tar file at path.
func writeSquashed(layers []v1.Layer, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating squashed tar: %w", err)
	}
	if err := flatten(layers, f); err != nil {
		//nolint:errcheck,gosec // close is best-effort; we already have an error to surface
		f.Close()
		return fmt.Errorf("flattening image: %w", err)
	}
	return f.Close()
}

// copyWithContext copies src to dst, aborting when ctx is canceled.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 256*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tarEntrySpec describes one entry of a synthetic layer tar.
type tarEntrySpec struct {
	name     string
	typeflag byte
	content  string
	linkname string
}

func file(name, content string) tarEntrySpec {
	return tarEntrySpec{name: name, typeflag: tar.TypeReg, content: content}
}

func dir(name string) tarEntrySpec {
	return tarEntrySpec{name: name, typeflag: tar.TypeDir}
}

func symlink(name, target string) tarEntrySpec {
	return tarEntrySpec{name: name, typeflag: tar.TypeSymlink, linkname: target}
}

// makeLayer builds a gzipped layer from the given entries.
func makeLayer(t *testing.T, entries ...tarEntrySpec) v1.Layer {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Linkname: e.linkname,
			Mode:     0o755,
			Size:     int64(len(e.content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if e.content != "" {
			_, err := tw.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	return layer
}

// makeImage assembles a synthetic image from layers.
func makeImage(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)
	return img
}

func TestSquashToFS(t *testing.T) {
	t.Parallel()

	// Layer 1: base filesystem with a file that will be overwritten, one
	// that will be whiteouted, an opaque-dir candidate, and symlinks.
	l1 := makeLayer(t,
		dir("etc"),
		file("etc/version", "v1"),
		file("etc/removed.txt", "delete me"),
		dir("opq"),
		file("opq/old.txt", "hidden by opaque dir"),
		dir("usr"), dir("usr/lib"),
		file("usr/lib/os-release", "ID=testos\n"),
		symlink("etc/os-release", "../usr/lib/os-release"),
		symlink("lib", "usr/lib"),
	)
	// Layer 2: overwrites, whiteouts, and an opaque directory.
	l2 := makeLayer(t,
		file("etc/version", "v2"),
		file("etc/.wh.removed.txt", ""),
		tarEntrySpec{name: "opq/.wh..wh..opq", typeflag: tar.TypeReg},
		file("opq/new.txt", "fresh"),
	)

	fsys, cleanup, err := squashToFS(t.Context(), makeImage(t, l1, l2), nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup()) })

	// Layer ordering: the later layer wins.
	got, err := fs.ReadFile(fsys, "etc/version")
	require.NoError(t, err)
	assert.Equal(t, "v2", string(got))

	// Whiteout: the file from layer 1 is gone.
	_, err = fs.Stat(fsys, "etc/removed.txt")
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Opaque dir: layer-1 contents hidden, layer-2 contents present.
	_, err = fs.Stat(fsys, "opq/old.txt")
	require.ErrorIs(t, err, fs.ErrNotExist)
	got, err = fs.ReadFile(fsys, "opq/new.txt")
	require.NoError(t, err)
	assert.Equal(t, "fresh", string(got))

	// File symlink: reading through etc/os-release lands on usr/lib.
	got, err = fs.ReadFile(fsys, "etc/os-release")
	require.NoError(t, err)
	assert.Equal(t, "ID=testos\n", string(got))

	// Directory symlink: paths through lib/ resolve into usr/lib/.
	got, err = fs.ReadFile(fsys, "lib/os-release")
	require.NoError(t, err)
	assert.Equal(t, "ID=testos\n", string(got))

	// Directory listing works for explicit and implicit directories.
	entries, err := fs.ReadDir(fsys, "etc")
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"os-release", "version"}, names)
}

func TestSquashToFSConformance(t *testing.T) {
	t.Parallel()

	// fstest.TestFS exercises the full fs.FS contract (Open semantics,
	// ReadDir consistency, path validation, ...) over a symlink-free image.
	l := makeLayer(t,
		dir("a"),
		file("a/b.txt", "b"),
		file("a/c.txt", "c"),
		dir("a/d"),
		file("a/d/e.txt", "e"),
		file("top.txt", "top"),
	)
	fsys, cleanup, err := squashToFS(t.Context(), makeImage(t, l), nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup()) })

	require.NoError(t,
		fstest.TestFS(fsys, "a/b.txt", "a/c.txt", "a/d/e.txt", "top.txt"))
}

func TestSquashToFSHooks(t *testing.T) {
	t.Parallel()

	l1 := makeLayer(t, file("one.txt", "1"))
	l2 := makeLayer(t, file("two.txt", "2"))

	var mu sync.Mutex
	started := map[string]int64{}
	finished := map[string]bool{}
	progressed := map[string]int64{}

	hooks := &PullHooks{
		LayerStart: func(digest string, total int64) {
			mu.Lock()
			defer mu.Unlock()
			started[digest] = total
		},
		LayerProgress: func(digest string, complete, _ int64) {
			mu.Lock()
			defer mu.Unlock()
			progressed[digest] = complete
		},
		LayerDone: func(digest string) {
			mu.Lock()
			defer mu.Unlock()
			finished[digest] = true
		},
	}

	fsys, cleanup, err := squashToFS(t.Context(), makeImage(t, l1, l2), hooks)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup()) })
	require.NotNil(t, fsys)

	// Both layers reported start, full progress, and completion.
	require.Len(t, started, 2)
	require.Len(t, finished, 2)
	for digest, total := range started {
		assert.True(t, finished[digest], "layer %s never finished", digest)
		assert.Equal(t, total, progressed[digest],
			"layer %s progress did not reach its total", digest)
	}
}

func TestSquashToFSCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, cleanup, err := squashToFS(ctx, makeImage(t, makeLayer(t, file("x", "y"))), nil)
	if cleanup != nil {
		//nolint:errcheck,gosec // best-effort cleanup in test
		cleanup()
	}
	require.ErrorIs(t, err, context.Canceled)
}

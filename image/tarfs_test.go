// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTarFileRandomAccess verifies that files opened from a squashed image
// support io.ReaderAt and io.Seeker, and that random reads stay within the
// file's own bytes rather than leaking into neighboring tar entries.
func TestTarFileRandomAccess(t *testing.T) {
	t.Parallel()

	fsys, cleanup, err := squashToFS(t.Context(), makeImage(t, makeLayer(t,
		dir("bin"),
		file("bin/before", "AAAAAAAA"),
		file("bin/target", "0123456789"),
		file("bin/after", "ZZZZZZZZ"),
	)), nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup()) })

	f, err := fsys.Open("bin/target")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	ra, ok := f.(io.ReaderAt)
	require.True(t, ok, "tar files must implement io.ReaderAt")
	seeker, ok := f.(io.Seeker)
	require.True(t, ok, "tar files must implement io.Seeker")

	// ReadAt in the middle of the file.
	buf := make([]byte, 4)
	n, err := ra.ReadAt(buf, 3)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "3456", string(buf))

	// ReadAt past the end is bounded to this entry: short read plus EOF,
	// never bytes from the next tar entry.
	buf = make([]byte, 8)
	n, err = ra.ReadAt(buf, 6)
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 4, n)
	assert.Equal(t, "6789", string(buf[:n]))

	// ReadAt does not move the sequential read position.
	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "0123456789", string(got))

	// Seek rewinds and repositions the sequential reader.
	pos, err := seeker.Seek(-3, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(7), pos)
	got, err = io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "789", string(got))
}

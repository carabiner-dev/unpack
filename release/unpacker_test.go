// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// newTestUnpacker returns a release unpacker whose default decomposer is
// replaced by one driving the fake backend.
func newTestUnpacker(backend Backend) *Unpacker {
	u := NewUnpacker()
	u.RegisterDecomposer(newTestDecomposer(backend))
	return u
}

// TestUnpackerExtract runs the release unpacker against a valid reference,
// exercising the full chain: subject routing, decomposer dispatch and the
// NodeList shape.
func TestUnpackerExtract(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeBackend{md: testMetadata(), artifacts: testArtifacts()})

	nodelists, err := u.Extract(t.Context(), testReference())
	require.NoError(t, err)
	require.Len(t, nodelists, 1)

	roots := nodelists[0].GetRootNodes()
	require.Len(t, roots, 1)
	assert.Equal(t, "widget", roots[0].GetName())
	assert.Len(t, nodelists[0].GetNodes(), 3)
}

// TestUnpackerRejectsNonReleaseSubject covers the routing guard: passing
// something that isn't a release Reference (or nil) is a programmer error.
func TestUnpackerRejectsNonReleaseSubject(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()

	_, err := u.Extract(t.Context(), nil)
	require.Error(t, err)

	_, err = u.Extract(t.Context(), bogusSubject{})
	require.ErrorContains(t, err, `subject of type "bogus"`)
}

// TestUnpackerRegistry checks that the init() registration routes release
// subjects to this unpacker through the shared registry.
func TestUnpackerRegistry(t *testing.T) {
	t.Parallel()
	u, err := api.UnpackerFor(testReference())
	require.NoError(t, err)
	require.NotNil(t, u)

	ru, ok := u.(*Unpacker)
	require.True(t, ok, "registry returned an unpacker of type %T", u)

	ru.RegisterDecomposer(newTestDecomposer(&fakeBackend{
		md: testMetadata(), artifacts: testArtifacts(),
	}))
	nodelists, err := ru.Extract(t.Context(), testReference())
	require.NoError(t, err)
	require.Len(t, nodelists, 1)
}

// TestUnpackerRegisterUnregisterDecomposer covers the decomposer registry
// round trip: unregistering the default decomposer leaves nothing to run, and
// registering one brings extraction back.
func TestUnpackerRegisterUnregisterDecomposer(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	u.UnregisterDecomposer(NewDecomposer())

	nodelists, err := u.Extract(t.Context(), testReference())
	require.NoError(t, err)
	assert.Empty(t, nodelists)

	u.RegisterDecomposer(newTestDecomposer(&fakeBackend{
		md: testMetadata(), artifacts: testArtifacts(),
	}))
	nodelists, err = u.Extract(t.Context(), testReference())
	require.NoError(t, err)
	require.Len(t, nodelists, 1)
}

type bogusSubject struct{}

func (bogusSubject) DecomposableType() string { return "bogus" }

// Sanity check: the bogusSubject still satisfies the api.DecomposableSubject
// interface so that the test compiles.
var _ api.DecomposableSubject = bogusSubject{}

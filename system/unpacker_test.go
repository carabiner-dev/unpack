// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// TestUnpackerExtractLocalSystem runs the SystemPackages unpacker against a
// LocalSystem subject rooted at the RPM fixture. It exercises the full chain:
// subject routing, FileSystem(), decomposer dispatch, and NodeList shape.
func TestUnpackerExtractLocalSystem(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	subject := &LocalSystem{Root: "rpm/testdata/rhel8-libuuid"}

	nodelists, err := u.Extract(context.Background(), subject)
	require.NoError(t, err)
	require.Len(t, nodelists, 1, "expected exactly one NodeList (from rpm)")

	nodes := nodelists[0].GetNodes()
	require.Len(t, nodes, 1)
	assert.Equal(t, "libuuid", nodes[0].GetName())
	assert.Equal(t,
		"pkg:rpm/rhel/libuuid@2.32.1-42.el8_8?arch=x86_64&distro=rhel-8.8&upstream=util-linux-2.32.1-42.el8_8.src.rpm",
		nodes[0].GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
	)
}

// TestUnpackerExtractLocalSystemIncludeFiles flips the IncludeFiles option
// on the unpacker and verifies that file nodes flow all the way through to
// the NodeList — exercising the full Options → DecomposerOptions plumbing.
func TestUnpackerExtractLocalSystemIncludeFiles(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	u.Options.IncludeFiles = true
	subject := &LocalSystem{Root: "rpm/testdata/rhel8-libuuid"}

	nodelists, err := u.Extract(context.Background(), subject)
	require.NoError(t, err)
	require.Len(t, nodelists, 1)

	// 1 package + 7 files in the libuuid fixture.
	assert.Len(t, nodelists[0].GetNodes(), 8)
}

// TestUnpackerExtractEmptySystem confirms that a system with no recognized
// package databases produces no NodeLists (rather than an error or a NodeList
// with zero nodes).
func TestUnpackerExtractEmptySystem(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	subject := &LocalSystem{Root: t.TempDir()}

	nodelists, err := u.Extract(context.Background(), subject)
	require.NoError(t, err)
	assert.Empty(t, nodelists)
}

// TestUnpackerRejectsNonSystemSubject covers the routing guard: passing
// something that isn't a System (or nil) is a programmer error.
func TestUnpackerRejectsNonSystemSubject(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()

	_, err := u.Extract(context.Background(), nil)
	require.Error(t, err)

	_, err = u.Extract(context.Background(), bogusSubject{})
	require.Error(t, err)
}

type bogusSubject struct{}

func (bogusSubject) DecomposableType() string { return "bogus" }

// Sanity check: the bogusSubject still satisfies the api.DecomposableSubject
// interface so that the test compiles.
var _ api.DecomposableSubject = bogusSubject{}

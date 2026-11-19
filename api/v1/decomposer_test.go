// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

type contextKey struct{}

// plainDecomposer takes no context.
type plainDecomposer struct{ ran bool }

func (p *plainDecomposer) Extract(*DecomposerOptions) (*sbom.NodeList, error) {
	p.ran = true
	return sbom.NewNodeList(), nil
}
func (p *plainDecomposer) Requirements(*DecomposerOptions) []Requirement { return nil }
func (p *plainDecomposer) DefaultOptions() any                           { return nil }

// contextDecomposer takes one, and keeps what it carried.
type contextDecomposer struct {
	plainDecomposer
	carried any
}

func (c *contextDecomposer) ExtractWithContext(ctx context.Context, _ *DecomposerOptions) (*sbom.NodeList, error) {
	c.carried = ctx.Value(contextKey{})
	return sbom.NewNodeList(), nil
}

// TestExtractWithContext checks a decomposer that takes a context is run
// with the caller's, and one that does not is run all the same.
func TestExtractWithContext(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(t.Context(), contextKey{}, "carried")

	with := &contextDecomposer{}
	nl, err := ExtractWithContext(ctx, with, &DecomposerOptions{})
	require.NoError(t, err)
	require.NotNil(t, nl)
	require.Equal(t, "carried", with.carried)
	require.False(t, with.ran, "the method that takes the context is the one run")

	plain := &plainDecomposer{}
	nl, err = ExtractWithContext(ctx, plain, &DecomposerOptions{})
	require.NoError(t, err)
	require.NotNil(t, nl)
	require.True(t, plain.ran)
}

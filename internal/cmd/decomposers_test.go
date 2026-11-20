// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/unpack/dependencies"
	"github.com/carabiner-dev/unpack/source/sbt"
)

func TestDecomposerOptions(t *testing.T) {
	t.Parallel()

	t.Run("nothing asked", func(t *testing.T) {
		t.Parallel()
		unpacker := dependencies.NewUnpacker()
		opts := &decomposerOptions{}
		require.NoError(t, opts.ValidateDecomposers())
		require.NoError(t, opts.ApplyDecomposers(unpacker))
		require.Empty(t, unpacker.Options.Decomposers)
	})

	t.Run("switches reach the unpacker", func(t *testing.T) {
		t.Parallel()
		unpacker := dependencies.NewUnpacker()
		opts := &decomposerOptions{Enable: []string{"golang"}, Disable: []string{"npm", "ruby"}}
		require.NoError(t, opts.ValidateDecomposers())
		require.NoError(t, opts.ApplyDecomposers(unpacker))
		require.Equal(t, map[string]bool{"golang": true, "npm": false, "ruby": false}, unpacker.Options.Decomposers)
	})

	t.Run("enabled and disabled", func(t *testing.T) {
		t.Parallel()
		opts := &decomposerOptions{Enable: []string{"npm"}, Disable: []string{"npm"}}
		require.ErrorContains(t, opts.ValidateDecomposers(), `"npm" is both enabled and disabled`)
	})

	t.Run("an unknown name", func(t *testing.T) {
		t.Parallel()
		unpacker := dependencies.NewUnpacker()
		for _, opts := range []*decomposerOptions{{Enable: []string{"golan"}}, {Disable: []string{"golan"}}} {
			err := opts.ApplyDecomposers(unpacker)
			require.ErrorContains(t, err, `unknown decomposer "golan"`)
			require.ErrorContains(t, err, "golang, maven, npm")
			require.Empty(t, unpacker.Options.Decomposers)
		}
	})

	t.Run("sbt needs its snapshot", func(t *testing.T) {
		t.Parallel()
		unpacker := dependencies.NewUnpacker()
		opts := &decomposerOptions{Enable: []string{sbtName}}
		require.ErrorContains(t, opts.ApplyDecomposers(unpacker), "--sbt-snapshot")

		// Once its flag registered it, it is a name like the others.
		unpacker.RegisterDecomposerAs(sbtName, sbt.New("snapshot.json"))
		require.NoError(t, (&decomposerOptions{Disable: []string{sbtName}}).ApplyDecomposers(unpacker))
		require.Equal(t, map[string]bool{sbtName: false}, unpacker.Options.Decomposers)
	})
}

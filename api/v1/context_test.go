// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1_test

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact/gobinary"
	"github.com/carabiner-dev/unpack/artifact/rustbinary"
	"github.com/carabiner-dev/unpack/release"
	"github.com/carabiner-dev/unpack/source/composer"
	"github.com/carabiner-dev/unpack/source/golang"
	"github.com/carabiner-dev/unpack/source/maven"
	"github.com/carabiner-dev/unpack/source/npm"
	"github.com/carabiner-dev/unpack/source/python"
	"github.com/carabiner-dev/unpack/source/ruby"
	"github.com/carabiner-dev/unpack/source/rust"
	"github.com/carabiner-dev/unpack/source/sbt"
	"github.com/carabiner-dev/unpack/system/apk"
	syscomposer "github.com/carabiner-dev/unpack/system/composer"
	"github.com/carabiner-dev/unpack/system/deb"
	syspython "github.com/carabiner-dev/unpack/system/python"
	"github.com/carabiner-dev/unpack/system/rpm"
)

// TestDecomposerContexts pins the context each decomposer says it reads
// in. It is what the documents made from their data state about how they
// were made, so a decomposer changing it, or a new one saying nothing,
// should be a decision and not an accident.
func TestDecomposerContexts(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		decomposer api.Decomposer
		expected   api.GenerationContext
	}{
		// What a source tree states, before any build.
		"composer": {composer.New(), api.ContextSource},
		"golang":   {golang.New(), api.ContextSource},
		"maven":    {maven.New(), api.ContextSource},
		"npm":      {npm.New(), api.ContextSource},
		"python":   {python.New(), api.ContextSource},
		"ruby":     {ruby.New(), api.ContextSource},
		"rust":     {rust.New(), api.ContextSource},

		// What the build tool recorded of its own resolution.
		"sbt": {sbt.New(""), api.ContextBuild},

		// What something already built holds.
		"gobinary":        {gobinary.New(), api.ContextAnalyzed},
		"rustbinary":      {rustbinary.New(), api.ContextAnalyzed},
		"release":         {release.NewDecomposer(), api.ContextAnalyzed},
		"apk":             {apk.New(), api.ContextAnalyzed},
		"deb":             {deb.New(), api.ContextAnalyzed},
		"rpm":             {rpm.New(), api.ContextAnalyzed},
		"system python":   {syspython.New(), api.ContextAnalyzed},
		"system composer": {syscomposer.New(), api.ContextAnalyzed},
	} {
		context, ok := api.GenerationContextOf(tc.decomposer)
		require.True(t, ok, "%s does not say in what context it reads", name)
		require.Equal(t, tc.expected, context, name)
	}
}

// silent is a decomposer that says nothing of its context.
type silent struct{}

func (silent) Extract(*api.DecomposerOptions) (*sbom.NodeList, error) { return sbom.NewNodeList(), nil }
func (silent) Requirements(*api.DecomposerOptions) []api.Requirement  { return nil }
func (silent) DefaultOptions() any                                    { return nil }

func TestGenerationContextOfSilent(t *testing.T) {
	t.Parallel()
	_, ok := api.GenerationContextOf(silent{})
	require.False(t, ok)
}

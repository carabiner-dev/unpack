// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1_test

import (
	"context"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact/gobinary"
	"github.com/carabiner-dev/unpack/artifact/rustbinary"
	"github.com/carabiner-dev/unpack/release"
	"github.com/carabiner-dev/unpack/source/cmake"
	"github.com/carabiner-dev/unpack/source/composer"
	"github.com/carabiner-dev/unpack/source/conan"
	"github.com/carabiner-dev/unpack/source/golang"
	"github.com/carabiner-dev/unpack/source/gradle"
	"github.com/carabiner-dev/unpack/source/maven"
	"github.com/carabiner-dev/unpack/source/npm"
	"github.com/carabiner-dev/unpack/source/nuget"
	"github.com/carabiner-dev/unpack/source/pkgconf"
	"github.com/carabiner-dev/unpack/source/python"
	"github.com/carabiner-dev/unpack/source/ruby"
	"github.com/carabiner-dev/unpack/source/rust"
	"github.com/carabiner-dev/unpack/source/sbt"
	"github.com/carabiner-dev/unpack/source/swift"
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
		"cmake":    {cmake.New(), api.ContextSource},
		"conan":    {conan.New(), api.ContextSource},
		"pkgconf":  {pkgconf.New(), api.ContextSource},
		"swift":    {swift.New(), api.ContextSource},
		"nuget":    {nuget.New(), api.ContextSource},
		"gradle":   {gradle.New(), api.ContextSource},
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
		generation, ok := api.GenerationContextOf(tc.decomposer)
		require.True(t, ok, "%s does not say in what context it reads", name)
		require.Equal(t, tc.expected, generation, name)
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

func TestExtractionContexts(t *testing.T) {
	t.Parallel()

	// Each context once, sorted, whatever order they are met in.
	e := api.NewExtraction(sbom.NewNodeList(), api.ContextAnalyzed, api.ContextSource, api.ContextAnalyzed)
	require.Equal(t, []api.GenerationContext{api.ContextSource, api.ContextAnalyzed}, e.Contexts)

	e.AddContexts(api.ContextBuild, api.ContextSource)
	require.Equal(t, []api.GenerationContext{api.ContextSource, api.ContextBuild, api.ContextAnalyzed}, e.Contexts)

	// A decomposer that says, and one that does not.
	said := api.NewExtraction(sbom.NewNodeList())
	said.AddContextOf(golang.New())
	said.AddContextOf(silent{})
	require.Equal(t, []api.GenerationContext{api.ContextSource}, said.Contexts)

	require.Empty(t, api.NewExtraction(sbom.NewNodeList()).Contexts)

	merged := api.MergedContexts([]*api.Extraction{
		api.NewExtraction(nil, api.ContextAnalyzed),
		api.NewExtraction(nil),
		api.NewExtraction(nil, api.ContextSource, api.ContextAnalyzed),
	})
	require.Equal(t, []api.GenerationContext{api.ContextSource, api.ContextAnalyzed}, merged)
	require.Empty(t, api.MergedContexts(nil))
}

// plainUnpacker only knows how to extract node lists.
type plainUnpacker struct{ lists []*sbom.NodeList }

func (p plainUnpacker) Extract(context.Context, api.DecomposableSubject) ([]*sbom.NodeList, error) {
	return p.lists, nil
}
func (plainUnpacker) RegisterDecomposer(api.Decomposer)   {}
func (plainUnpacker) UnregisterDecomposer(api.Decomposer) {}

// tellingUnpacker also says in what context it read them.
type tellingUnpacker struct{ plainUnpacker }

func (u tellingUnpacker) Extractions(context.Context, api.DecomposableSubject) ([]*api.Extraction, error) {
	extractions := make([]*api.Extraction, 0, len(u.lists))
	for _, nl := range u.lists {
		extractions = append(extractions, api.NewExtraction(nl, api.ContextAnalyzed))
	}
	return extractions, nil
}

// TestExtractions checks an unpacker is asked for its extractions when it
// can give them, and that one that cannot has its node lists returned with
// nothing said of them.
func TestExtractions(t *testing.T) {
	t.Parallel()

	lists := []*sbom.NodeList{sbom.NewNodeList(), sbom.NewNodeList()}

	plain, err := api.Extractions(context.Background(), plainUnpacker{lists}, nil)
	require.NoError(t, err)
	require.Equal(t, lists, api.NodeLists(plain))
	for _, e := range plain {
		require.Empty(t, e.Contexts)
	}

	telling, err := api.Extractions(context.Background(), tellingUnpacker{plainUnpacker{lists}}, nil)
	require.NoError(t, err)
	require.Equal(t, lists, api.NodeLists(telling))
	for _, e := range telling {
		require.Equal(t, []api.GenerationContext{api.ContextAnalyzed}, e.Contexts)
	}

	require.Nil(t, api.NodeLists(nil))
}

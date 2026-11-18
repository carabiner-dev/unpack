// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestModuleSupplier(t *testing.T) {
	t.Parallel()

	type supplier struct{ name, url string }
	for modPath, expected := range map[string]*supplier{
		// On a code host, the owner of the repository, as the path
		// spells it.
		"github.com/spf13/cobra":              {"spf13", "https://github.com/spf13"},
		"github.com/go-git/go-git/v5":         {"go-git", "https://github.com/go-git"},
		"github.com/BurntSushi/toml":          {"BurntSushi", "https://github.com/BurntSushi"},
		"gitlab.com/gitlab-org/api/client-go": {"gitlab-org", "https://gitlab.com/gitlab-org"},
		"codeberg.org/someone/thing":          {"someone", "https://codeberg.org/someone"},

		// Elsewhere, the domain the path is served from.
		"golang.org/x/mod":           {"golang.org", "https://golang.org"},
		"google.golang.org/protobuf": {"google.golang.org", "https://google.golang.org"},
		"sigs.k8s.io/release-utils":  {"sigs.k8s.io", "https://sigs.k8s.io"},
		"go.uber.org/zap":            {"go.uber.org", "https://go.uber.org"},
		"filippo.io/edwards25519":    {"filippo.io", "https://filippo.io"},
		"example.com":                {"example.com", "https://example.com"},

		// gopkg.in redirects onto GitHub and supplies nothing itself.
		"gopkg.in/yaml.v3":                 {"go-yaml", "https://github.com/go-yaml"},
		"gopkg.in/check.v1":                {"go-check", "https://github.com/go-check"},
		"gopkg.in/natefinch/lumberjack.v2": {"natefinch", "https://github.com/natefinch"},

		// Paths that name nobody.
		"github.com": nil,
		"gopkg.in":   nil,
		"gopkg.in/":  nil,
		"stdlib":     nil,
		"mymodule":   nil,
		"":           nil,
	} {
		got := moduleSupplier(modPath)
		if expected == nil {
			require.Nil(t, got, modPath)
			continue
		}
		require.NotNil(t, got, modPath)
		require.Equal(t, *expected, supplier{got.GetName(), got.GetUrl()}, modPath)
		require.True(t, got.GetIsOrg(), modPath)
		require.Empty(t, got.GetEmail(), modPath)
	}
}

// TestNodeSuppliers checks the suppliers reach the graph: on every module
// the build holds and on the standard library, and not on the main module,
// whose supplier is for whoever writes the document to state.
func TestNodeSuppliers(t *testing.T) {
	t.Parallel()

	d := Decomposer{}
	set := &ModuleSet{
		Main:      Module{Path: "github.com/example/app"},
		GoVersion: "1.24.0",
		Requires: []Module{
			{Path: "github.com/spf13/cobra", Version: "v1.10.2"},
			{Path: "golang.org/x/mod", Version: "v0.43.0"},
		},
	}
	set.Modules = append(set.Modules, set.Requires...)

	nl, err := d.BuildNodeList(set, &api.DecomposerOptions{Networking: api.NetworkDisabled})
	require.NoError(t, err)

	suppliers := map[string]string{}
	for _, n := range nl.GetNodes() {
		require.LessOrEqual(t, len(n.GetSuppliers()), 1)
		for _, s := range n.GetSuppliers() {
			suppliers[n.GetName()] = s.GetName()
		}
	}
	require.Equal(t, map[string]string{
		"github.com/spf13/cobra": "spf13",
		"golang.org/x/mod":       "golang.org",
		"stdlib":                 "The Go Authors",
	}, suppliers)

	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.Empty(t, root.GetSuppliers())
	require.Equal(t, sbom.Node_PACKAGE, root.GetType())
}

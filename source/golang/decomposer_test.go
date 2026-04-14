// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"fmt"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestParseLocalGoMod(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		modFile, err := d.parseLocalGoMod("testdata/simple/go.mod")
		require.NoError(t, err)
		require.NotNil(t, modFile)
		require.Equal(t, "example.com/simple", modFile.Module.Mod.Path)
		require.Len(t, modFile.Require, 2)
	})

	t.Run("nofile", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		_, err := d.parseLocalGoMod("testdata/nonexistent/go.mod")
		require.Error(t, err)
	})

	t.Run("with-replace", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		modFile, err := d.parseLocalGoMod("testdata/with-replace/go.mod")
		require.NoError(t, err)
		require.NotNil(t, modFile)
		require.Equal(t, "example.com/with-replace", modFile.Module.Mod.Path)
		require.Len(t, modFile.Replace, 1)
		require.Equal(t, "github.com/old/module", modFile.Replace[0].Old.Path)
		require.Equal(t, "github.com/new/module", modFile.Replace[0].New.Path)
		require.Equal(t, "v1.1.0", modFile.Replace[0].New.Version)
	})

	t.Run("this-repo", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		modFile, err := d.parseLocalGoMod("../../go.mod")
		require.NoError(t, err)
		require.NotNil(t, modFile)
		require.Equal(t, "github.com/carabiner-dev/unpack", modFile.Module.Mod.Path)
	})
}

func TestParseGoSum(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		hashes, err := d.parseGoSum("testdata/simple/go.sum")
		require.NoError(t, err)
		require.NotNil(t, hashes)

		// Check that we have hashes for both modules
		require.Contains(t, hashes, "github.com/google/uuid@v1.3.0")
		require.Contains(t, hashes, "golang.org/x/text@v0.3.0")

		// Each module has h1 and go.mod hashes
		require.GreaterOrEqual(t, len(hashes["github.com/google/uuid@v1.3.0"]), 1)
	})

	t.Run("nofile", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		_, err := d.parseGoSum("testdata/nonexistent/go.sum")
		require.Error(t, err)
	})
}

func TestBuildDependencyTree(t *testing.T) {
	t.Parallel()

	d := Decomposer{}
	modFile, err := d.parseLocalGoMod("testdata/simple/go.mod")
	require.NoError(t, err)

	trees, err := d.buildDependencyTree(modFile, "testdata/simple/go.mod", &defaultOptions)
	require.NoError(t, err)
	require.NotNil(t, trees)

	// Check root module has direct dependencies
	rootDeps := (*trees)["example.com/simple"]
	require.Len(t, rootDeps, 2)
	require.Contains(t, rootDeps, "github.com/google/uuid@v1.3.0")
	require.Contains(t, rootDeps, "golang.org/x/text@v0.3.0")
}

func TestBuildDependencyTreeWithReplace(t *testing.T) {
	t.Parallel()

	d := Decomposer{}
	modFile, err := d.parseLocalGoMod("testdata/with-replace/go.mod")
	require.NoError(t, err)

	trees, err := d.buildDependencyTree(modFile, "testdata/with-replace/go.mod", &defaultOptions)
	require.NoError(t, err)
	require.NotNil(t, trees)

	// Check that replace directive was applied
	rootDeps := (*trees)["example.com/with-replace"]
	require.Len(t, rootDeps, 2)
	// github.com/old/module should be replaced with github.com/new/module@v1.1.0
	require.Contains(t, rootDeps, "github.com/new/module@v1.1.0")
	require.Contains(t, rootDeps, "github.com/another/dep@v1.2.0")
}

func TestResolveModule(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	replaces := map[string]replaceTarget{
		"github.com/old/module":          {Path: "github.com/new/module", Version: "v2.0.0"},
		"github.com/versioned@v1.0.0":    {Path: "github.com/versioned", Version: "v1.1.0"},
		"github.com/version-only@v1.0.0": {Path: "", Version: "v1.2.0"},
	}

	tests := []struct {
		name        string
		path        string
		version     string
		wantPath    string
		wantVersion string
	}{
		{
			name:        "no replace",
			path:        "github.com/unchanged/module",
			version:     "v1.0.0",
			wantPath:    "github.com/unchanged/module",
			wantVersion: "v1.0.0",
		},
		{
			name:        "module-level replace",
			path:        "github.com/old/module",
			version:     "v1.0.0",
			wantPath:    "github.com/new/module",
			wantVersion: "v2.0.0",
		},
		{
			name:        "version-specific replace",
			path:        "github.com/versioned",
			version:     "v1.0.0",
			wantPath:    "github.com/versioned",
			wantVersion: "v1.1.0",
		},
		{
			name:        "version-only replace",
			path:        "github.com/version-only",
			version:     "v1.0.0",
			wantPath:    "github.com/version-only",
			wantVersion: "v1.2.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotPath, gotVersion := d.resolveModule(tc.path, tc.version, replaces)
			require.Equal(t, tc.wantPath, gotPath)
			require.Equal(t, tc.wantVersion, gotVersion)
		})
	}
}

func TestIsLocalReplace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path  string
		local bool
	}{
		{"./local", true},
		{"../parent", true},
		{"/absolute/path", true},
		{"github.com/remote/module", false},
		{"golang.org/x/text", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.local, isLocalReplace(tc.path))
		})
	}
}

func TestConvertTree(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	// Manually create a tree structure similar to what buildDependencyTree produces
	trees := &map[string][]string{
		"github.com/knqyf263/go-rpmdb@v0.1.1": {
			"github.com/glebarez/go-sqlite@v1.20.3",
			"github.com/hashicorp/go-multierror@v1.1.1",
			"github.com/stretchr/testify@v1.7.0",
			"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			"github.com/davecgh/go-spew@v1.1.0",
			"github.com/dustin/go-humanize@v1.0.1",
			"github.com/google/uuid@v1.3.0",
			"github.com/hashicorp/errwrap@v1.0.0",
			"github.com/mattn/go-isatty@v0.0.17",
			"github.com/pmezard/go-difflib@v1.0.0",
			"github.com/remyoudompheng/bigfft@v0.0.0-20230126093431-47fa9a501578",
			"golang.org/x/sys@v0.4.0",
			"gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c",
			"modernc.org/libc@v1.22.2",
			"modernc.org/mathutil@v1.5.0",
			"modernc.org/memory@v1.5.0",
			"modernc.org/sqlite@v1.20.3",
		},
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		nl := sbom.NewNodeList()
		nl.AddRootNode(&sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    "github.com/knqyf263/go-rpmdb",
			Version: "v0.1.1",
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): goStringToPurl("github.com/knqyf263/go-rpmdb@v0.1.1"),
			},
		})

		err := d.convertTree(nl, []string{"github.com/knqyf263/go-rpmdb@v0.1.1"}, trees, &map[string]struct{}{})
		require.NoError(t, err)

		// This is the list of all the entries from the expected nodes
		list := []string{
			"github.com/knqyf263/go-rpmdb@v0.1.1",
			"github.com/glebarez/go-sqlite@v1.20.3",
			"github.com/hashicorp/go-multierror@v1.1.1",
			"github.com/stretchr/testify@v1.7.0",
			"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			"github.com/davecgh/go-spew@v1.1.0",
			"github.com/dustin/go-humanize@v1.0.1",
			"github.com/google/uuid@v1.3.0",
			"github.com/hashicorp/errwrap@v1.0.0",
			"github.com/mattn/go-isatty@v0.0.17",
			"github.com/pmezard/go-difflib@v1.0.0",
			"github.com/remyoudompheng/bigfft@v0.0.0-20230126093431-47fa9a501578",
			"golang.org/x/sys@v0.4.0",
			"gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c",
			"modernc.org/libc@v1.22.2",
			"modernc.org/mathutil@v1.5.0",
			"modernc.org/memory@v1.5.0",
			"modernc.org/sqlite@v1.20.3",
		}

		// Extract the nodelist data
		nodes := nl.GetNodes()
		reslist := make([]string, 0, len(nodes))
		for _, n := range nodes {
			reslist = append(reslist, fmt.Sprintf("%s@%s", n.GetName(), n.GetVersion()))
		}

		sort.Strings(reslist)
		sort.Strings(list)
		require.Equal(t, list, reslist)

		require.Len(t, nl.GetEdges(), 1)
		require.Len(t, nl.GetRootElements(), 1)
		require.Equal(t, nl.GetRootElements()[0], nl.GetEdges()[0].GetFrom())
		require.Len(t, nl.GetEdges()[0].GetTo(), 17)

		require.Equal(t, "pkg:golang/github.com/knqyf263/go-rpmdb@v0.1.1", string(nl.GetRootNodes()[0].Purl()))
	})

	t.Run("no-deps", func(t *testing.T) {
		err := d.convertTree(sbom.NewNodeList(), []string{"invalid"}, trees, &map[string]struct{}{})
		require.Error(t, err)
	})

	t.Run("no-node", func(t *testing.T) {
		err := d.convertTree(sbom.NewNodeList(), []string{"sigs.k8s.io/bom"}, trees, &map[string]struct{}{})
		require.Error(t, err)
	})
}

func TestConvertTrees(t *testing.T) {
	t.Parallel()
	d := Decomposer{}

	// Create tree structure
	trees := &map[string][]string{
		"sigs.k8s.io/bom": {
			"github.com/knqyf263/go-rpmdb@v0.1.1",
		},
		"github.com/knqyf263/go-rpmdb@v0.1.1": {
			"github.com/glebarez/go-sqlite@v1.20.3",
			"github.com/hashicorp/go-multierror@v1.1.1",
			"github.com/stretchr/testify@v1.7.0",
			"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			"github.com/davecgh/go-spew@v1.1.0",
			"github.com/dustin/go-humanize@v1.0.1",
			"github.com/google/uuid@v1.3.0",
			"github.com/hashicorp/errwrap@v1.0.0",
			"github.com/mattn/go-isatty@v0.0.17",
			"github.com/pmezard/go-difflib@v1.0.0",
			"github.com/remyoudompheng/bigfft@v0.0.0-20230126093431-47fa9a501578",
			"golang.org/x/sys@v0.4.0",
			"gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c",
			"modernc.org/libc@v1.22.2",
			"modernc.org/mathutil@v1.5.0",
			"modernc.org/memory@v1.5.0",
			"modernc.org/sqlite@v1.20.3",
		},
	}

	t.Run("two-branches", func(t *testing.T) {
		t.Parallel()
		root := "sigs.k8s.io/bom"
		nl, err := d.convertTrees(&api.DecomposerOptions{}, root, trees, "")
		require.NoError(t, err)
		require.NotNil(t, nl)

		// sigs.k8s.io/bom
		//     \
		//   github.com/knqyf263/go-rpmdb@v0.1.1
		//      |- github.com/glebarez/go-sqlite@v1.20.3
		//      |- github.com/hashicorp/go-multierror@v1.1.1
		//      |- github.com/stretchr/testify@v1.7.0
		//      |- golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1
		//      |- github.com/davecgh/go-spew@v1.1.0
		//     ...
		//
		require.Equal(t, nl.GetNodes()[0].GetName(), root)
		require.Len(t, nl.GetEdges(), 2)
		require.Len(t, nl.GetRootElements(), 1)
		require.Equal(t, nl.GetRootElements()[0], nl.GetEdges()[0].GetFrom())
		require.Len(t, nl.GetEdges()[1].GetTo(), 17)
	})
}

func TestExtract(t *testing.T) {
	t.Parallel()

	d := New()

	opts := &api.DecomposerOptions{
		WorkDir: "testdata/simple",
	}

	nl, err := d.Extract(opts)
	require.NoError(t, err)
	require.NotNil(t, nl)

	// Check root node
	require.Len(t, nl.GetRootElements(), 1)
	rootNodes := nl.GetRootNodes()
	require.Len(t, rootNodes, 1)
	require.Equal(t, "example.com/simple", rootNodes[0].GetName())

	// Check we have nodes for dependencies
	require.Len(t, nl.GetNodes(), 3) // root + 2 deps
}

func TestRequirements(t *testing.T) {
	t.Parallel()
	d := New()
	reqs := d.Requirements(nil)
	require.Nil(t, reqs, "Pure Go implementation should not require external binaries")
}

func TestGoStringToPurl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{
			input: "github.com/google/uuid@v1.3.0",
			want:  "pkg:golang/github.com/google/uuid@v1.3.0",
		},
		{
			input: "golang.org/x/text@v0.3.0",
			want:  "pkg:golang/golang.org/x/text@v0.3.0",
		},
		{
			input: "github.com/user/repo",
			want:  "pkg:golang/github.com/user/repo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := goStringToPurl(tc.input)
			require.Equal(t, tc.want, got)
		})
	}
}

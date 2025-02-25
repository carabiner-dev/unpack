package golang

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/carabiner-dev/unpack/source"
	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestReadMainModule(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		name, err := d.readMainModule(&source.Options{
			WorkDir: "../..",
		})
		require.NoError(t, err)
		require.Equal(t, "github.com/carabiner-dev/unpack", name)
	})

	t.Run("nofile", func(t *testing.T) {
		t.Parallel()
		d := Decomposer{}
		_, err := d.readMainModule(&source.Options{})
		require.Error(t, err)
	})
}

func TestParseGoGraph(t *testing.T) {
	d := Decomposer{}
	data, err := os.ReadFile("testdata/output.txt")
	require.NoError(t, err)
	trees, err := d.parseGoGraph(string(data))
	require.NoError(t, err)
	require.NotNil(t, trees)

	// The output file has 64 unique modules
	require.Len(t, *trees, 64)

	// The main component has 72 dependencies. These come from go.mod's
	// direct and indirect for some reason
	require.Len(t, (*trees)["sigs.k8s.io/bom"], 72)
}

func TestConvertTree(t *testing.T) {
	t.Parallel()
	d := Decomposer{}
	// data, err := os.ReadFile("testdata/output.txt")
	data, err := os.ReadFile("testdata/onepackage.txt")

	require.NoError(t, err)
	trees, err := d.parseGoGraph(string(data))
	require.NoError(t, err)

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
		reslist := []string{}
		for _, n := range nl.GetNodes() {
			reslist = append(reslist, fmt.Sprintf("%s@%s", n.Name, n.Version))
		}

		sort.Strings(reslist)
		sort.Strings(list)
		require.Equal(t, list, reslist)

		require.Len(t, nl.Edges, 1)
		require.Len(t, nl.RootElements, 1)
		require.Equal(t, nl.RootElements[0], nl.Edges[0].From)
		require.Len(t, nl.Edges[0].To, 17)

		require.Equal(t, string(nl.GetRootNodes()[0].Purl()), "pkg:golang/github.com/knqyf263/go-rpmdb@v0.1.1")
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
	data, err := os.ReadFile("testdata/onepackage.txt")
	require.NoError(t, err)
	trees, err := d.parseGoGraph(string(data))
	require.NoError(t, err)

	t.Run("two-branches", func(t *testing.T) {
		root := "sigs.k8s.io/bom"
		nl, err := d.convertTrees(root, trees)
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
		require.Equal(t, nl.Nodes[0].Name, root)
		require.Len(t, nl.Edges, 2)
		require.Len(t, nl.RootElements, 1)
		require.Equal(t, nl.RootElements[0], nl.Edges[0].From)
		require.Len(t, nl.Edges[1].To, 17)
	})
}

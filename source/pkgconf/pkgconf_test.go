// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pkgconf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

func TestParseDependencies(t *testing.T) {
	t.Parallel()
	for list, expected := range map[string][]Dependency{
		"":                 {},
		"zlib":             {{Name: "zlib"}},
		"libssl libcrypto": {{Name: "libssl"}, {Name: "libcrypto"}},
		"libssl, libcrypto,gtk+-3.0": {
			{Name: "libssl"}, {Name: "libcrypto"}, {Name: "gtk+-3.0"},
		},
		"libdrm >=  2.4.133":       {{Name: "libdrm", Operator: ">=", Version: "2.4.133"}},
		"openssl>=3.0":             {{Name: "openssl", Operator: ">=", Version: "3.0"}},
		"a = 1.0, b != 2 c<3 d<=4": {{"a", "=", "1.0"}, {"b", "!=", "2"}, {"c", "<", "3"}, {"d", "<=", "4"}},
		"glib-2.0 > 2.50 gio-2.0":  {{Name: "glib-2.0", Operator: ">", Version: "2.50"}, {Name: "gio-2.0"}},
		"pkg >= 1:2.3~rc1+b":       {{Name: "pkg", Operator: ">=", Version: "1:2.3~rc1+b"}},
		// What a template leaves: a placeholder for a name, for a
		// version, and one that became nothing.
		"zlib @EXTRA@ openssl":  {{Name: "zlib"}, {Name: "openssl"}},
		"core = @VERSION@ zlib": {{Name: "core"}, {Name: "zlib"}},
		"@PKG@ >= 1.0 zlib":     {{Name: "zlib"}},
		"zlib >=":               {{Name: "zlib"}},
		">= 1.0":                {},
	} {
		require.Equal(t, expected, ParseDependencies(list), list)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	file, err := ReadFile("testdata/project/libdemo.pc.in")
	require.NoError(t, err)
	require.Equal(t, "libdemo", file.ID)
	require.Equal(t, "Demo", file.Name)
	require.Equal(t, "A demonstration library", file.Description)
	require.Equal(t, "https://example.org/demo", file.URL)
	require.Equal(t, []string{"MIT", "Apache-2.0"}, file.Licenses)
	require.Equal(t, "Demo Team <team@example.org>", file.Maintainer)
	require.Equal(t, []string{"2020-2026 Demo Authors", "2019 Someone Else"}, file.Copyright)

	// What the build fills in is not known: the version, the source it
	// names, the path under the prefix, and part of two lists.
	require.Empty(t, file.Version)
	require.Empty(t, file.Source)
	require.Empty(t, file.LicenseFile)
	require.Equal(t, []string{"Version", "License.file", "Source", "Requires", "Requires.private", "Libs", "Cflags"}, file.Unresolved)

	// The entries of a list that are settled are read, and a line
	// carries on after a backslash.
	require.Equal(t, []Dependency{
		{Name: "zlib", Operator: ">=", Version: "1.2.11"},
		{Name: "libdemo-core"},
		{Name: "pkgconf", Operator: ">=", Version: "1.9.0"},
	}, file.Requires)
	require.Equal(t, []Dependency{{Name: "openssl", Operator: ">=", Version: "3.0"}, {Name: "libcrypto"}}, file.RequiresPrivate)

	file, err = ReadFile("testdata/project/libdemo-core.pc")
	require.NoError(t, err)
	require.Equal(t, "2.4.1", file.Version, "a variable of the file is expanded")
	require.Equal(t, "The core of the demonstration library", file.Description, "a comment ends the line")
	require.Empty(t, file.Unresolved)
	require.Equal(t, []Dependency{{Name: "libunwind"}}, file.RequiresInternal)
	require.Equal(t, []Dependency{{Name: "libdl-shim", Operator: "!=", Version: "0.9"}}, file.RequiresShared)

	// Keywords in any case, an escaped reference and an escaped hash, a
	// variable defined after its use, and lines that are nothing.
	file = Parse("odd", "NAME: odd\nversion: 1.0\nDescription: costs $${price} \\# each\nURL: ${later}\nlater=x\nnot a line\n")
	require.Equal(t, "odd", file.Name)
	require.Equal(t, "1.0", file.Version)
	require.Equal(t, `costs ${price} \# each`, file.Description)
	require.Empty(t, file.URL)
	require.Equal(t, []string{"URL"}, file.Unresolved)

	_, err = ReadFile("testdata/project/missing.pc")
	require.Error(t, err)
}

func properties(node *sbom.Node) map[string][]string {
	out := map[string][]string{}
	for _, property := range node.GetProperties() {
		out[property.GetName()] = append(out[property.GetName()], property.GetData())
	}
	return out
}

func extract(t *testing.T, dir string, opts *api.DecomposerOptions) (roots, nodes map[string]*sbom.Node, edges map[string]sbom.Edge_Type) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)

	byID := map[string]*sbom.Node{}
	nodes = map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
		nodes[node.GetName()] = node
	}
	require.Len(t, nodes, len(byID), "a package is one node")
	roots = map[string]*sbom.Node{}
	for _, node := range nl.GetRootNodes() {
		roots[node.GetName()] = node
	}
	edges = map[string]sbom.Edge_Type{}
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			edges[byID[e.GetFrom()].GetName()+" -> "+byID[to].GetName()] = e.GetType()
		}
	}
	return roots, nodes, edges
}

func TestExtract(t *testing.T) {
	t.Parallel()
	roots, nodes, edges := extract(t, "testdata/project", &api.DecomposerOptions{})

	// Each file is a package the project installs.
	require.Len(t, roots, 2)
	require.Contains(t, roots, "libdemo")
	require.Contains(t, roots, "libdemo-core")

	// Every list is a dependency. One package of the project requiring
	// the other is related to it, and the pkgconf virtual is no package.
	require.Equal(t, map[string]sbom.Edge_Type{
		"libdemo -> zlib":            sbom.Edge_dependsOn,
		"libdemo -> libdemo-core":    sbom.Edge_dependsOn,
		"libdemo -> openssl":         sbom.Edge_dependsOn,
		"libdemo -> libcrypto":       sbom.Edge_dependsOn,
		"libdemo-core -> zlib":       sbom.Edge_dependsOn,
		"libdemo-core -> libunwind":  sbom.Edge_dependsOn,
		"libdemo-core -> libdl-shim": sbom.Edge_dependsOn,
	}, edges)
	require.NotContains(t, nodes, "pkgconf")

	demo := roots["libdemo"]
	require.Empty(t, demo.GetVersion(), "the template does not say")
	require.Equal(t, "pkg:generic/libdemo", string(demo.Purl()))
	require.Equal(t, "A demonstration library", demo.GetDescription())
	require.Equal(t, "https://example.org/demo", demo.GetUrlHome())
	require.Empty(t, demo.GetUrlDownload())
	require.Equal(t, []string{"MIT", "Apache-2.0"}, demo.GetLicenses())
	require.Equal(t, "2020-2026 Demo Authors\n2019 Someone Else", demo.GetCopyright())
	require.Len(t, demo.GetSuppliers(), 1)
	require.Equal(t, "Demo Team", demo.GetSuppliers()[0].GetName())
	require.Equal(t, "team@example.org", demo.GetSuppliers()[0].GetEmail())
	require.Equal(t, map[string][]string{
		PropertyName:       {"Demo"},
		PropertyFile:       {"libdemo.pc.in"},
		PropertyUnresolved: {"Version", "License.file", "Source", "Requires", "Requires.private", "Libs", "Cflags"},
	}, properties(demo))

	core := roots["libdemo-core"]
	require.Equal(t, "2.4.1", core.GetVersion())
	require.Equal(t, "pkg:generic/libdemo-core@2.4.1", string(core.Purl()))
	require.Equal(t, map[string][]string{PropertyFile: {"libdemo-core.pc"}}, properties(core),
		"a package of the project keeps its own properties, whoever requires it")

	// A required package has no version, only what the requirements say:
	// through which lists, and which versions will do.
	require.Empty(t, nodes["zlib"].GetVersion())
	require.Equal(t, "pkg:generic/zlib", string(nodes["zlib"].Purl()))
	require.Equal(t, map[string][]string{
		PropertyRequires:   {"requires"},
		PropertyConstraint: {">= 1.2.11"},
	}, properties(nodes["zlib"]))
	require.Equal(t, map[string][]string{
		PropertyRequires:   {"requires.private"},
		PropertyConstraint: {">= 3.0"},
	}, properties(nodes["openssl"]))
	require.Equal(t, []string{"requires.internal"}, properties(nodes["libunwind"])[PropertyRequires])
	require.Equal(t, []string{"requires.shared"}, properties(nodes["libdl-shim"])[PropertyRequires])
	require.Equal(t, []string{"!= 0.9"}, properties(nodes["libdl-shim"])[PropertyConstraint])

	// A version from the caller names every package of the project.
	roots, _, _ = extract(t, "testdata/project", &api.DecomposerOptions{Version: "v3.0.0", CommitHash: "abc"})
	require.Equal(t, "v3.0.0", roots["libdemo"].GetVersion())
	require.Equal(t, "v3.0.0", roots["libdemo-core"].GetVersion())
	require.Len(t, roots["libdemo"].GetExternalReferences(), 1)
}

// TestExtractFileOverTemplate checks a package there as a file and as the
// template it was made from is read from the file.
func TestExtractFileOverTemplate(t *testing.T) {
	t.Parallel()
	roots, _, edges := extract(t, "testdata/template", &api.DecomposerOptions{})
	require.Len(t, roots, 1)
	require.Equal(t, "3.1.0", roots["both"].GetVersion())
	require.Equal(t, map[string]sbom.Edge_Type{"both -> fromfile": sbom.Edge_dependsOn}, edges)
	require.Equal(t, []string{"both.pc"}, properties(roots["both"])[PropertyFile])
}

func TestExtractNothing(t *testing.T) {
	t.Parallel()
	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.ErrorContains(t, err, "no pkg-config files")
}

func TestMaintainer(t *testing.T) {
	t.Parallel()
	for value, expected := range map[string]*sbom.Person{
		"Demo Team <team@example.org>":      {Name: "Demo Team", Email: "team@example.org"},
		"team@example.org":                  {Name: "team@example.org", Email: "team@example.org"},
		"Demo Team https://example.org/who": {Name: "Demo Team", Url: "https://example.org/who"},
		"Demo Team <https://example.org>":   {Name: "Demo Team", Url: "https://example.org"},
		"Demo Team":                         {Name: "Demo Team"},
		"":                                  nil,
	} {
		got := maintainer(value)
		if expected == nil {
			require.Nil(t, got, value)
			continue
		}
		require.Equal(t, expected.GetName(), got.GetName(), value)
		require.Equal(t, expected.GetEmail(), got.GetEmail(), value)
		require.Equal(t, expected.GetUrl(), got.GetUrl(), value)
	}
}

// proC is the start of a Pro*C source, which goes by the same suffix.
const proC = `#include <stdio.h>
EXEC SQL INCLUDE SQLCA;
/* Name: not a property, it is in a comment of another language */
int main(void) {
    EXEC SQL CONNECT :username IDENTIFIED BY :password;
    return 0;
}
`

func TestValid(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		content string
		missing []string
	}{
		"a pkg-config file":          {"Name: a\nDescription: b\nVersion: 1\n", []string{}},
		"a template":                 {"Name: @NAME@\nDescription: @DESC@\nVersion: @VERSION@\n", []string{}},
		"keywords in another case":   {"NAME: a\ndescription: b\nVERSION: 1\n", []string{}},
		"empty values still declare": {"Name:\nDescription:\nVersion:\n", []string{}},
		"no version":                 {"Name: a\nDescription: b\n", []string{"Version"}},
		"only variables":             {"prefix=/usr\nlibdir=${prefix}/lib\n", []string{"Name", "Description", "Version"}},
		"a Pro*C source":             {proC, []string{"Name", "Description", "Version"}},
		"an empty file":              {"", []string{"Name", "Description", "Version"}},
	} {
		file := Parse("x", tc.content)
		require.Equal(t, tc.missing, file.Missing(), name)
		require.Equal(t, len(tc.missing) == 0, file.Valid(), name)
	}
}

// TestOtherFilesAreSkipped checks things that are called .pc and are no
// pkg-config files make no codebase, and are left out of one that has
// real ones beside them.
func TestOtherFilesAreSkipped(t *testing.T) {
	t.Parallel()
	write := func(dir, name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	const genuine = "Name: real\nDescription: a library\nVersion: 1.0\nRequires: zlib\n"

	other := t.TempDir()
	write(other, "query.pc", proC)
	mixed := t.TempDir()
	write(mixed, "query.pc", proC)
	write(mixed, "real.pc", genuine)

	index := code.PathIndex{}
	index.Add(other, "query.pc")
	index.Add(mixed, "query.pc")
	index.Add(mixed, "real.pc")
	index.Add("gone", "missing.pc")
	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{mixed}, found)

	roots, nodes, _ := extract(t, mixed, &api.DecomposerOptions{})
	require.Len(t, roots, 1)
	require.Contains(t, roots, "real")
	require.NotContains(t, nodes, "query")

	_, err = New().Extract(&api.DecomposerOptions{WorkDir: other})
	require.ErrorContains(t, err, "no pkg-config files")
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	const valid = "Name: a\nDescription: b\nVersion: 1\n"
	lib, installed, src := t.TempDir(), t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(lib, "libdemo.pc.in"), []byte(valid), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(installed, "zlib.pc"), []byte(valid), 0o600))

	index := code.PathIndex{}
	index.Add(lib, "libdemo.pc.in")
	index.Add(lib, "CMakeLists.txt")
	index.Add(installed, "zlib.pc")
	index.Add(src, "main.c")
	index.Add(src, "notes.pc.txt")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{installed, lib}, found)
}

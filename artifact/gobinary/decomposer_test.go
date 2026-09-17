// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gobinary

import (
	"bytes"
	"os"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/golang"
)

// The module every test binary in this repository belongs to.
const thisModule = "github.com/carabiner-dev/unpack"

// openSelf opens the running test binary, which is a Go executable with
// build information like any other.
func openSelf(t *testing.T) *os.File {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	f, err := os.Open(exe)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

func TestTraits(t *testing.T) {
	t.Parallel()
	d := New()
	assert.Equal(t, "gobinary", d.Name())
	assert.ElementsMatch(t, []string{"image", "system"}, d.DefaultSubjects())
	assert.Nil(t, d.Requirements(nil))
	assert.Equal(t, golang.New().DefaultOptions(), d.DefaultOptions())
}

func TestMatches(t *testing.T) {
	t.Parallel()
	d := New()
	for name, tc := range map[string]struct {
		header []byte
		want   bool
	}{
		"elf":              {[]byte("\x7fELF\x02\x01\x01"), true},
		"pe":               {[]byte("MZ\x90\x00\x03"), true},
		"macho64 le":       {[]byte("\xcf\xfa\xed\xfe\x07"), true},
		"macho32 be":       {[]byte("\xfe\xed\xfa\xce\x00"), true},
		"script":           {[]byte("#!/bin/sh\n"), false},
		"text":             {[]byte("hello world"), false},
		"short":            {[]byte("\x7fE"), false},
		"empty":            {nil, false},
		"self test binary": {selfHeader(t), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, d.Matches(nil, tc.header))
		})
	}
}

func selfHeader(t *testing.T) []byte {
	t.Helper()
	f := openSelf(t)
	header := make([]byte, 64)
	n, err := f.ReadAt(header, 0)
	require.NoError(t, err)
	return header[:n]
}

func TestExtractArtifactSelf(t *testing.T) {
	t.Parallel()
	f := openSelf(t)

	nl, err := New().ExtractArtifact(f, "gobinary.test", &api.DecomposerOptions{
		Networking: api.NetworkDisabled,
	})
	require.NoError(t, err)
	require.NotNil(t, nl)

	roots := nl.GetRootElements()
	require.Len(t, roots, 1)
	root := nl.GetNodeByID(roots[0])
	require.NotNil(t, root)
	assert.Equal(t, thisModule, root.GetName())
	assert.Equal(t, "pkg:golang/"+thisModule, root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)],
		"a test binary's main module is (devel), which leaves the purl unversioned")
	assert.Equal(t, []sbom.Purpose{sbom.Purpose_APPLICATION}, root.GetPrimaryPurpose())

	props := map[string]string{}
	for _, p := range root.GetProperties() {
		props[p.GetName()] = p.GetData()
	}
	assert.Equal(t, runtime.GOOS, props[PropertyGOOS])
	assert.Equal(t, runtime.GOARCH, props[PropertyGOARCH])
	assert.Equal(t, thisModule+"/artifact/gobinary.test", props[PropertyPackage])

	// Modules linked into this very binary are in the graph, with their
	// checksums, hanging off the root.
	protobom := nl.GetNodesByIdentifier("purl", "pkg:golang/github.com/protobom/protobom@"+versionOf(t, "github.com/protobom/protobom"))
	require.Len(t, protobom, 1)
	assert.NotEmpty(t, protobom[0].GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	stdlib := nl.GetNodesByIdentifier("purl", "pkg:golang/stdlib@"+goRelease(runtime.Version()))
	require.Len(t, stdlib, 1)

	// The root depends on every linked module. Edges among the modules
	// themselves may or may not be there, depending on what the local
	// module cache holds, so only the root's are checked.
	var rootDeps []string
	for _, e := range nl.GetEdges() {
		assert.Equal(t, sbom.Edge_dependsOn, e.GetType())
		if e.GetFrom() == root.GetId() {
			rootDeps = append(rootDeps, e.GetTo()...)
		}
	}
	assert.Contains(t, rootDeps, protobom[0].GetId())
	assert.Contains(t, rootDeps, stdlib[0].GetId())
	bi, ok := debug.ReadBuildInfo()
	require.True(t, ok)
	assert.Len(t, rootDeps, len(bi.Deps)+1, "every linked module plus the stdlib")
}

// versionOf reads a dependency's version from the test binary's own build info.
func versionOf(t *testing.T, path string) string {
	t.Helper()
	bi, ok := debug.ReadBuildInfo()
	require.True(t, ok)
	for _, dep := range bi.Deps {
		if dep.Path == path {
			return dep.Version
		}
	}
	t.Fatalf("%s is not linked into the test binary", path)
	return ""
}

func TestExtractArtifactDisowns(t *testing.T) {
	t.Parallel()
	d := New()
	for name, data := range map[string][]byte{
		"not an executable": []byte("just some text, long enough to not be a short read at all"),
		"elf header only":   append([]byte("\x7fELF\x02\x01\x01\x00"), make([]byte, 120)...),
		"empty":             {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nl, err := d.ExtractArtifact(bytes.NewReader(data), name, nil)
			require.NoError(t, err)
			assert.Nil(t, nl)
		})
	}
}

func TestExtract(t *testing.T) {
	t.Parallel()
	d := New()

	_, err := d.Extract(nil)
	require.Error(t, err)
	_, err = d.Extract(&api.DecomposerOptions{})
	require.Error(t, err)
	_, err = d.Extract(&api.DecomposerOptions{WorkDir: "/nonexistent/binary"})
	require.Error(t, err)

	exe, err := os.Executable()
	require.NoError(t, err)
	nl, err := d.Extract(&api.DecomposerOptions{WorkDir: exe, Networking: api.NetworkDisabled})
	require.NoError(t, err)
	require.NotNil(t, nl)
	assert.Equal(t, thisModule, nl.GetNodeByID(nl.GetRootElements()[0]).GetName())
}

func TestExtractArtifactVersionOverride(t *testing.T) {
	t.Parallel()
	f := openSelf(t)
	nl, err := New().ExtractArtifact(f, "gobinary.test", &api.DecomposerOptions{
		Version:    "v9.9.9",
		CommitHash: "abc123",
		Networking: api.NetworkDisabled,
	})
	require.NoError(t, err)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	assert.Equal(t, "pkg:golang/"+thisModule+"@v9.9.9", root.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
	require.Len(t, root.GetExternalReferences(), 1)
	assert.Equal(t, "abc123", root.GetExternalReferences()[0].GetHashes()[int32(sbom.HashAlgorithm_SHA1)])
}

func TestModuleSetFromBuildInfo(t *testing.T) {
	t.Parallel()
	bi := &debug.BuildInfo{
		GoVersion: "go1.24.0",
		Path:      "example.com/app/cmd/app",
		Main:      debug.Module{Path: "example.com/app", Version: "v1.2.3"},
		Deps: []*debug.Module{
			{Path: "example.com/lib", Version: "v0.1.0", Sum: "h1:lib"},
			{Path: "example.com/nosum", Version: "v0.2.0"},
			{
				Path: "example.com/old", Version: "v1.0.0", Sum: "h1:old",
				Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1", Sum: "h1:fork"},
			},
			{
				Path: "example.com/local", Version: "v3.0.0",
				Replace: &debug.Module{Path: "../local", Version: "(devel)"},
			},
			{Path: "example.com/lib", Version: "v0.1.0", Sum: "h1:lib"},
			nil,
		},
		Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}},
	}

	set := ModuleSetFromBuildInfo(bi)
	assert.Equal(t, golang.Module{Path: "example.com/app", Version: "v1.2.3"}, set.Main)
	assert.Equal(t, "1.24.0", set.GoVersion)

	want := []golang.Module{
		{Path: "example.com/lib", Version: "v0.1.0", Sums: []string{"h1:lib"}},
		{Path: "example.com/nosum", Version: "v0.2.0"},
		// The replacement is what was linked.
		{Path: "example.com/fork", Version: "v1.0.1", Sums: []string{"h1:fork"}},
		// A local replacement keeps the original module.
		{Path: "example.com/local", Version: "v3.0.0"},
	}
	assert.Equal(t, want, set.Requires, "every linked module is required by the root, once")
	assert.Equal(t, want, set.Modules)
	assert.Equal(t, map[string]golang.Replacement{
		"example.com/old":        {Path: "example.com/fork", Version: "v1.0.1"},
		"example.com/old@v1.0.0": {Path: "example.com/fork", Version: "v1.0.1"},
	}, set.Replaces)

	// Without a main module the main package stands in.
	set = ModuleSetFromBuildInfo(&debug.BuildInfo{GoVersion: "go1.22", Path: "command-line-arguments"})
	assert.Equal(t, "command-line-arguments", set.Main.Path)
	assert.Equal(t, "1.22", set.GoVersion)
	assert.Empty(t, set.Modules)
}

func TestGoRelease(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"go1.24.0":                        "1.24.0",
		"go1.22":                          "1.22",
		"devel go1.25-0123abcd Mon Jan 1": "1.25-0123abcd",
		"devel":                           "",
		"":                                "",
		"go":                              "",
	} {
		assert.Equal(t, want, goRelease(in), in)
	}
}

func TestIsLocalPath(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"./fork": true, "../fork": true, "/abs/fork": true, ".": true, "..": true,
		"example.com/fork": false, "": false,
	} {
		assert.Equal(t, want, isLocalPath(in), in)
	}
}

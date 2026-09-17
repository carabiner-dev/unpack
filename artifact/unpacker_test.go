// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact/gobinary"
	"github.com/carabiner-dev/unpack/internal/testbin"
)

// fakeDecomposer claims files whose contents start with its magic and
// renders each as one package node named after the rest of the content.
type fakeDecomposer struct {
	name     string
	magic    string
	subjects []string
	failOn   string // path whose extraction fails
	rejects  string // path Matches accepts but ExtractArtifact disowns
}

var (
	_ Decomposer          = (*fakeDecomposer)(nil)
	_ api.SubjectDefaults = (*fakeDecomposer)(nil)
)

func (f *fakeDecomposer) Name() string                                          { return f.name }
func (f *fakeDecomposer) DefaultSubjects() []string                             { return f.subjects }
func (f *fakeDecomposer) DefaultOptions() any                                   { return nil }
func (f *fakeDecomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }
func (f *fakeDecomposer) Extract(*api.DecomposerOptions) (*sbom.NodeList, error) {
	return nil, errors.New("not used")
}

func (f *fakeDecomposer) Matches(_ fs.FileInfo, header []byte) bool {
	return bytes.HasPrefix(header, []byte(f.magic))
}

func (f *fakeDecomposer) ExtractArtifact(ra io.ReaderAt, path string, _ *api.DecomposerOptions) (*sbom.NodeList, error) {
	if path == f.failOn {
		return nil, errors.New("boom")
	}
	if path == f.rejects {
		return nil, nil
	}
	data, err := io.ReadAll(io.NewSectionReader(ra, 0, 1<<20))
	if err != nil {
		return nil, err
	}
	nl := sbom.NewNodeList()
	nl.AddRootNode(&sbom.Node{
		Id:   uuid.NewString(),
		Type: sbom.Node_PACKAGE,
		Name: string(bytes.TrimPrefix(data, []byte(f.magic))),
	})
	return nl, nil
}

// plainDecomposer satisfies api.Decomposer only.
type plainDecomposer struct{}

func (plainDecomposer) DefaultOptions() any                                   { return nil }
func (plainDecomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }
func (plainDecomposer) Extract(*api.DecomposerOptions) (*sbom.NodeList, error) {
	return nil, nil
}

// noReaderAtFS hides io.ReaderAt from the files it opens, to exercise the
// in-memory fallback.
type noReaderAtFS struct{ fs.FS }

type sequentialFile struct{ fs.File }

func (n noReaderAtFS) Open(name string) (fs.File, error) {
	f, err := n.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return sequentialFile{f}, nil
}

func (n noReaderAtFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(n.FS, name)
}

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"bin/tool":      {Data: []byte("GOBIN example.com/tool"), Mode: 0o755},
		"bin/other":     {Data: []byte("ELF something else"), Mode: 0o755},
		"lib/plugin.so": {Data: []byte("GOBIN example.com/plugin"), Mode: 0o644},
		"etc/config":    {Data: []byte("key=value")},
		"empty":         {Data: []byte{}},
		"link":          {Data: []byte("bin/tool"), Mode: fs.ModeSymlink},
	}
}

// emptyUnpacker returns an unpacker with the default options and none of the
// built-in decomposers, so tests control exactly what runs.
func emptyUnpacker() *Unpacker {
	return &Unpacker{Options: DefaultOptions, decomposers: map[string]Decomposer{}}
}

func newTestUnpacker(decomposers ...Decomposer) *Unpacker {
	u := emptyUnpacker()
	for _, d := range decomposers {
		u.RegisterDecomposer(d)
	}
	return u
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func TestExtractFilesystem(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})

	lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS()})
	require.NoError(t, err)
	require.Len(t, lists, 2, "two files carry the magic")

	// Results come in path order.
	first := lists[0].GetNodeByID(lists[0].GetRootElements()[0])
	require.NotNil(t, first)
	assert.Equal(t, "bin/tool", first.GetName())
	assert.Equal(t, "bin/tool", first.GetFileName())
	assert.Equal(t, sbom.Node_FILE, first.GetType())
	assert.Equal(t, sha256Hex("GOBIN example.com/tool"), first.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	second := lists[1].GetNodeByID(lists[1].GetRootElements()[0])
	require.NotNil(t, second)
	assert.Equal(t, "lib/plugin.so", second.GetName())

	// The decomposer's graph hangs off the file node as generatedFrom.
	edges := lists[0].GetEdges()
	require.Len(t, edges, 1)
	assert.Equal(t, first.GetId(), edges[0].GetFrom())
	assert.Equal(t, sbom.Edge_generatedFrom, edges[0].GetType())
	require.Len(t, edges[0].GetTo(), 1)
	pkg := lists[0].GetNodeByID(edges[0].GetTo()[0])
	require.NotNil(t, pkg)
	assert.Equal(t, "example.com/tool", pkg.GetName())
	assert.Equal(t, sbom.Node_PACKAGE, pkg.GetType())
}

func TestExtractRestrictedPaths(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})

	lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS(), Only: []string{"lib/plugin.so", "etc/config"}})
	require.NoError(t, err)
	require.Len(t, lists, 1)
	root := lists[0].GetNodeByID(lists[0].GetRootElements()[0])
	assert.Equal(t, "lib/plugin.so", root.GetName())
}

func TestExtractFileSubject(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	require.NoError(t, os.WriteFile(path, []byte("GOBIN example.com/ondisk"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sibling"), []byte("GOBIN example.com/sibling"), 0o600))

	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})
	lists, err := u.Extract(t.Context(), &File{Path: path})
	require.NoError(t, err)
	require.Len(t, lists, 1, "only the named file is probed, not its siblings")
	root := lists[0].GetNodeByID(lists[0].GetRootElements()[0])
	assert.Equal(t, "tool", root.GetName())
	assert.Equal(t, sha256Hex("GOBIN example.com/ondisk"), root.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
}

func TestExtractReaderAtFallback(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})

	lists, err := u.Extract(t.Context(), &Filesystem{FS: noReaderAtFS{testFS()}})
	require.NoError(t, err)
	require.Len(t, lists, 2)
	root := lists[0].GetNodeByID(lists[0].GetRootElements()[0])
	// The whole file, header included, is what gets hashed and decomposed.
	assert.Equal(t, sha256Hex("GOBIN example.com/tool"), root.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	pkg := lists[0].GetNodeByID(lists[0].GetEdges()[0].GetTo()[0])
	assert.Equal(t, "example.com/tool", pkg.GetName())
}

func TestExtractErrorsAreJoined(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN ", failOn: "bin/tool"})

	lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS()})
	require.Error(t, err)
	require.ErrorContains(t, err, `decomposer "fake" on "bin/tool"`)
	require.Len(t, lists, 1, "the other artifact is still returned")
	root := lists[0].GetNodeByID(lists[0].GetRootElements()[0])
	assert.Equal(t, "lib/plugin.so", root.GetName())
}

func TestExtractDisownedFile(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN ", rejects: "bin/tool"})

	lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS()})
	require.NoError(t, err)
	require.Len(t, lists, 1)
}

func TestExtractSwitches(t *testing.T) {
	t.Parallel()

	t.Run("master switch off", func(t *testing.T) {
		t.Parallel()
		u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})
		u.Options.Enabled = false
		u.Options.Decomposers = map[string]bool{"fake": true}
		lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS()})
		require.NoError(t, err)
		assert.Empty(t, lists)
	})

	t.Run("decomposer off", func(t *testing.T) {
		t.Parallel()
		u := newTestUnpacker(
			&fakeDecomposer{name: "fake", magic: "GOBIN "},
			&fakeDecomposer{name: "elf", magic: "ELF "},
		)
		u.Options.Decomposers = map[string]bool{"fake": false}
		lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS()})
		require.NoError(t, err)
		require.Len(t, lists, 1)
		root := lists[0].GetNodeByID(lists[0].GetRootElements()[0])
		assert.Equal(t, "bin/other", root.GetName())
	})

	t.Run("no decomposers", func(t *testing.T) {
		t.Parallel()
		u := emptyUnpacker()
		lists, err := u.Extract(t.Context(), &Filesystem{FS: testFS()})
		require.NoError(t, err)
		assert.Empty(t, lists)
	})
}

func TestSkip(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"app/tool":            {Data: []byte("GOBIN example.com/app")},
		"app/vendor/helper":   {Data: []byte("GOBIN example.com/helper")},
		"opt/svc/bin/svc":     {Data: []byte("GOBIN example.com/svc")},
		"usr/bin/systool":     {Data: []byte("GOBIN example.com/systool")},
		"usr/lib/x/plugin":    {Data: []byte("GOBIN example.com/plugin")},
		"usr/local/bin/local": {Data: []byte("GOBIN example.com/local")},
		"bin/sh":              {Data: []byte("GOBIN example.com/sh")},
		"lib.so":              {Data: []byte("GOBIN example.com/lib.so")},
	}
	fake := &fakeDecomposer{name: "fake", magic: "GOBIN "}

	found := func(t *testing.T, opts Options, subject api.DecomposableSubject) []string {
		t.Helper()
		u := newTestUnpacker(fake)
		u.Options = opts
		u.Options.Enabled = true
		lists, err := u.Extract(t.Context(), subject)
		require.NoError(t, err)
		names := make([]string, 0, len(lists))
		for _, nl := range lists {
			names = append(names, nl.GetNodeByID(nl.GetRootElements()[0]).GetName())
		}
		return names
	}
	all := &Filesystem{FS: fsys}

	t.Run("nothing skipped", func(t *testing.T) {
		t.Parallel()
		assert.Len(t, found(t, Options{}, all), 8)
	})

	t.Run("anchored directories prune", func(t *testing.T) {
		t.Parallel()
		got := found(t, Options{Skip: []string{"/usr/bin/", "/usr/lib/", "/bin/"}}, all)
		assert.ElementsMatch(t, []string{"app/tool", "app/vendor/helper", "opt/svc/bin/svc", "usr/local/bin/local", "lib.so"}, got)
	})

	t.Run("unanchored directory matches at any depth", func(t *testing.T) {
		t.Parallel()
		got := found(t, Options{Skip: []string{"bin/"}}, all)
		assert.ElementsMatch(t, []string{"app/tool", "app/vendor/helper", "usr/lib/x/plugin", "lib.so"}, got)
	})

	t.Run("file globs and negation", func(t *testing.T) {
		t.Parallel()
		// As in git, a negation cannot re-include what a pruned parent
		// hides, so the exclusion targets the siblings, not the parent.
		got := found(t, Options{Skip: []string{"*.so", "/usr/*", "!/usr/local"}}, all)
		assert.ElementsMatch(t, []string{"app/tool", "app/vendor/helper", "opt/svc/bin/svc", "usr/local/bin/local", "bin/sh"}, got)
	})

	t.Run("blank patterns are ignored", func(t *testing.T) {
		t.Parallel()
		assert.Len(t, found(t, Options{Skip: []string{"", "  "}}, all), 8)
	})

	t.Run("system defaults", func(t *testing.T) {
		t.Parallel()
		got := found(t, Options{Skip: DefaultSystemSkips}, all)
		assert.ElementsMatch(t, []string{"app/tool", "app/vendor/helper", "opt/svc/bin/svc", "usr/local/bin/local", "lib.so"}, got)
	})

	t.Run("explicit paths are probed regardless", func(t *testing.T) {
		t.Parallel()
		got := found(t, Options{Skip: []string{"/usr/"}}, &Filesystem{FS: fsys, Only: []string{"usr/bin/systool"}})
		assert.Equal(t, []string{"usr/bin/systool"}, got)
	})
}

func TestDefaultsFor(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(
		&fakeDecomposer{name: "images-only", subjects: []string{"image", "system"}},
		&fakeDecomposer{name: "nowhere", subjects: nil},
	)
	// A decomposer without the trait runs everywhere.
	u.decomposers["untraited"] = &untraited{}

	opts := u.DefaultsFor("image")
	assert.True(t, opts.Enabled)
	assert.Equal(t, map[string]bool{"images-only": true, "nowhere": false, "untraited": true}, opts.Decomposers)

	opts = u.DefaultsFor("codebase")
	assert.Equal(t, map[string]bool{"images-only": false, "nowhere": false, "untraited": true}, opts.Decomposers)

	// Whole-system parents get the system skip list, a copy of it; the
	// rest skip nothing.
	assert.Equal(t, DefaultSystemSkips, u.DefaultsFor("image").Skip)
	assert.Equal(t, DefaultSystemSkips, u.DefaultsFor("system").Skip)
	assert.Nil(t, u.DefaultsFor("codebase").Skip)
	assert.Nil(t, u.DefaultsFor("").Skip)
	skips := u.DefaultsFor("image").Skip
	skips[0] = "changed"
	assert.NotEqual(t, "changed", DefaultSystemSkips[0])

	// DefaultsFor does not touch the unpacker's own options.
	assert.Nil(t, u.Options.Decomposers)
}

// untraited is an artifact decomposer with no SubjectDefaults.
type untraited struct{ plainDecomposer }

func (*untraited) Name() string                     { return "untraited" }
func (*untraited) Matches(fs.FileInfo, []byte) bool { return false }
func (*untraited) ExtractArtifact(io.ReaderAt, string, *api.DecomposerOptions) (*sbom.NodeList, error) {
	return nil, nil
}

func TestNewUnpacker(t *testing.T) {
	t.Parallel()
	u := NewUnpacker()
	assert.Equal(t, DefaultOptions, u.Options)

	// The built-in decomposers are registered under their names.
	require.Contains(t, u.decomposers, gobinary.Name)
	assert.Equal(t, gobinary.Name, u.decomposers[gobinary.Name].Name())

	// And their defaults are read by DefaultsFor.
	assert.True(t, u.DefaultsFor("image").Decomposers[gobinary.Name])
	assert.False(t, u.DefaultsFor("codebase").Decomposers[gobinary.Name])
}

// TestExtractGoBinary runs the default unpacker end to end on a real Go
// executable built for the purpose.
func TestExtractGoBinary(t *testing.T) {
	t.Parallel()
	exe, _ := testbin.Build(t)

	u := NewUnpacker()
	u.Options.Networking = api.NetworkDisabled
	lists, err := u.Extract(t.Context(), &File{Path: exe})
	require.NoError(t, err)
	require.Len(t, lists, 1)

	nl := lists[0]
	roots := nl.GetRootElements()
	require.Len(t, roots, 1)
	file := nl.GetNodeByID(roots[0])
	assert.Equal(t, sbom.Node_FILE, file.GetType())
	assert.Equal(t, filepath.Base(exe), file.GetName())
	assert.Len(t, file.GetHashes()[int32(sbom.HashAlgorithm_SHA256)], 64)

	// The file was generated from the unpack module, which depends on the
	// module linked into the fixture.
	var pkgs []string
	for _, e := range nl.GetEdges() {
		if e.GetFrom() == file.GetId() {
			assert.Equal(t, sbom.Edge_generatedFrom, e.GetType())
			pkgs = append(pkgs, e.GetTo()...)
		}
	}
	require.Len(t, pkgs, 1)
	pkg := nl.GetNodeByID(pkgs[0])
	assert.Equal(t, "github.com/carabiner-dev/unpack", pkg.GetName())
	assert.NotEmpty(t, nodesWithPurlPrefix(nl, "pkg:golang/github.com/google/uuid@"))
}

// nodesWithPurlPrefix returns the nodes whose purl starts with prefix.
func nodesWithPurlPrefix(nl *sbom.NodeList, prefix string) []*sbom.Node {
	var nodes []*sbom.Node
	for _, n := range nl.GetNodes() {
		if strings.HasPrefix(n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)], prefix) {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

func TestRegisterDecomposer(t *testing.T) {
	t.Parallel()
	u := emptyUnpacker()

	// Non-artifact decomposers are ignored.
	u.RegisterDecomposer(plainDecomposer{})
	assert.Empty(t, u.decomposers)

	d := &fakeDecomposer{name: "fake"}
	u.RegisterDecomposer(d)
	assert.Len(t, u.decomposers, 1)
	assert.Same(t, d, u.decomposers["fake"])

	// Re-registering the same name replaces.
	d2 := &fakeDecomposer{name: "fake", magic: "X"}
	u.RegisterDecomposer(d2)
	assert.Len(t, u.decomposers, 1)
	assert.Same(t, d2, u.decomposers["fake"])

	u.UnregisterDecomposer(plainDecomposer{})
	assert.Len(t, u.decomposers, 1)
	u.UnregisterDecomposer(d)
	assert.Empty(t, u.decomposers)
}

func TestExtractRejectsBadSubjects(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})

	_, err := u.Extract(t.Context(), nil)
	require.Error(t, err)

	_, err = u.Extract(t.Context(), otherSubject{})
	require.ErrorContains(t, err, `subject of type "other"`)

	_, err = u.Extract(t.Context(), &Filesystem{})
	require.ErrorContains(t, err, "no fs.FS")

	_, err = u.Extract(t.Context(), &File{})
	require.ErrorContains(t, err, "no path")
}

type otherSubject struct{}

func (otherSubject) DecomposableType() string { return "other" }

func TestExtractCanceledContext(t *testing.T) {
	t.Parallel()
	u := newTestUnpacker(&fakeDecomposer{name: "fake", magic: "GOBIN "})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := u.Extract(ctx, &Filesystem{FS: testFS()})
	require.ErrorIs(t, err, context.Canceled)
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	u, err := api.UnpackerFor(&Filesystem{FS: testFS()})
	require.NoError(t, err)
	assert.IsType(t, &Unpacker{}, u)
}

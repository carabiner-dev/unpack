// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/sync/errgroup"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact/gobinary"
	"github.com/carabiner-dev/unpack/artifact/rustbinary"
)

// Ensure the artifact unpacker satisfies the unified Unpacker interface.
var _ api.Unpacker = (*Unpacker)(nil)

// Register the artifact unpacker so that subjects of type "artifact" are routed
// here by the registry.
func init() {
	api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}

const defaultConcurrency = 4

// Options configures the artifact unpacker.
type Options struct {
	// Enabled is the master switch. When false no artifact is probed,
	// whatever the per-decomposer settings say.
	Enabled bool

	// Decomposers switches individual decomposers on or off by name. A
	// decomposer with no entry runs. DefaultsFor fills it from the
	// decomposers' own defaults for a given parent subject.
	Decomposers map[string]bool

	// Skip lists paths the scan leaves out, as gitignore-style patterns
	// relative to the source root: "/usr/lib/" prunes that directory tree,
	// "vendor/" prunes any directory of that name, "*.so" skips matching
	// files anywhere, and "!" negates. A pruned directory is never entered,
	// so as in git a negation cannot re-include anything below it. Paths
	// named explicitly (a File subject, a Filesystem restricted with Only)
	// are probed regardless.
	// DefaultsFor fills it with DefaultSystemSkips under parents that are
	// whole systems.
	Skip []string

	// Networking controls how much network access decomposers are allowed
	// when enriching what they read from the artifact.
	Networking api.NetworkLevel

	// IncludeBuild includes the dependencies that built an artifact, when
	// the artifact records them, related through buildDependency edges.
	IncludeBuild bool

	// Concurrency is how many files are probed at once.
	Concurrency int
}

// DefaultOptions is the configuration used by NewUnpacker: everything
// enabled, nothing skipped, essential networking.
var DefaultOptions = Options{
	Enabled:     true,
	Concurrency: defaultConcurrency,
}

// DefaultSystemSkips are the paths left out when scanning a whole system,
// such as a container image or a system root. They hold the distribution's
// own binaries and libraries, which belong to the installed packages the
// system decomposers inventory, and directories that never hold an
// application's executables. Skipping them keeps the scan to the places
// an application is installed in (/app, /opt, /usr/local, /home, the root)
// and keeps system components from being reported as artifacts.
var DefaultSystemSkips = []string{
	"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/",
	"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libx32/",
	"/usr/libexec/", "/usr/share/", "/usr/include/", "/usr/src/",
	"/etc/", "/var/", "/boot/", "/dev/", "/proc/", "/sys/", "/run/",
}

// systemRootParents are the parent subject types whose data is a whole
// system, where DefaultSystemSkips applies.
var systemRootParents = []string{"image", "system"}

// NewUnpacker returns an artifact unpacker with the default options and the
// built-in artifact decomposers.
func NewUnpacker() *Unpacker {
	return &Unpacker{
		Options: DefaultOptions,
		decomposers: map[string]Decomposer{
			gobinary.Name:   gobinary.New(),
			rustbinary.Name: rustbinary.New(),
		},
	}
}

// Unpacker reads dependency data out of built artifacts. It probes the files
// of its subject with the registered decomposers and returns one NodeList per
// artifact found, each rooted at a node describing the file.
type Unpacker struct {
	Options     Options
	decomposers map[string]Decomposer
}

// DefaultsFor returns the option set the unpacker should run with under a
// parent subject of the given type, such as "image": DefaultOptions with each
// registered decomposer switched on or off according to its own defaults,
// and, under a parent that is a whole system, DefaultSystemSkips as the
// skip list. Decomposers that implement api.SubjectDefaults run only under
// the parents they list; the rest run everywhere. Parents call this, adjust
// the result to what their caller asked for, and set it as the unpacker's
// Options.
func (u *Unpacker) DefaultsFor(parentSubjectType string) Options {
	opts := DefaultOptions
	if slices.Contains(systemRootParents, parentSubjectType) {
		opts.Skip = slices.Clone(DefaultSystemSkips)
	}
	opts.Decomposers = make(map[string]bool, len(u.decomposers))
	for name, d := range u.decomposers {
		enabled := true
		if sd, ok := d.(api.SubjectDefaults); ok {
			enabled = slices.Contains(sd.DefaultSubjects(), parentSubjectType)
		}
		opts.Decomposers[name] = enabled
	}
	return opts
}

// active returns the decomposers the options let run, in a stable order.
func (u *Unpacker) active() []Decomposer {
	if !u.Options.Enabled {
		return nil
	}
	names := make([]string, 0, len(u.decomposers))
	for name := range u.decomposers {
		if on, set := u.Options.Decomposers[name]; set && !on {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	ret := make([]Decomposer, 0, len(names))
	for _, name := range names {
		ret = append(ret, u.decomposers[name])
	}
	return ret
}

// Extract probes the files of the subject and returns one NodeList per
// artifact found. Each list is rooted at a file node carrying the artifact's
// path and SHA-256, related through a generatedFrom edge to the package graph
// the decomposer read out of it. A file no decomposer claims is skipped;
// an error reading one artifact does not stop the others and is returned,
// joined with the rest, alongside the lists that succeeded.
func (u *Unpacker) Extract(ctx context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
	if subject == nil {
		return nil, fmt.Errorf("artifact unpacker received a nil subject")
	}
	src, ok := subject.(Source)
	if !ok {
		return nil, fmt.Errorf(
			"artifact unpacker cannot process subject of type %q", subject.DecomposableType(),
		)
	}

	decomposers := u.active()
	if len(decomposers) == 0 {
		return nil, nil
	}

	fsys, err := src.FileSystem()
	if err != nil {
		return nil, fmt.Errorf("opening artifact source: %w", err)
	}

	paths := src.Paths()
	if paths == nil {
		if paths, err = regularFiles(fsys, skipMatcher(u.Options.Skip)); err != nil {
			return nil, fmt.Errorf("listing artifact source: %w", err)
		}
	}

	dOpts := &api.DecomposerOptions{
		Networking:   u.Options.Networking,
		IncludeBuild: u.Options.IncludeBuild,
	}

	// Probe the files concurrently, keeping results in path order.
	results := make([]*sbom.NodeList, len(paths))
	errs := make([]error, len(paths))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(u.Options.Concurrency, 1))
	for i, path := range paths {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			results[i], errs[i] = u.probe(fsys, path, decomposers, dOpts)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	var lists []*sbom.NodeList
	for _, nl := range results {
		if nl != nil {
			lists = append(lists, nl)
		}
	}
	return lists, errors.Join(errs...)
}

// probe runs the decomposers over one file. The first decomposer to claim
// the file wins; its graph is returned rooted at a node for the file.
func (u *Unpacker) probe(fsys fs.FS, path string, decomposers []Decomposer, dOpts *api.DecomposerOptions) (*sbom.NodeList, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only file

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}

	header := make([]byte, HeaderSize)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	header = header[:n]

	var candidates []Decomposer
	for _, d := range decomposers {
		if d.Matches(info, header) {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	ra, err := readerAt(f, header, info.Size())
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	for _, d := range candidates {
		nl, err := d.ExtractArtifact(ra, path, dOpts)
		if err != nil {
			return nil, fmt.Errorf("decomposer %q on %q: %w", d.Name(), path, err)
		}
		if nl == nil {
			continue
		}
		return wrapInFile(nl, path, ra, info.Size())
	}
	return nil, nil
}

// readerAt returns random access to an open file. Files that support it
// natively are used in place; the rest are read into memory, prepending
// the header already consumed.
func readerAt(f fs.File, header []byte, size int64) (io.ReaderAt, error) {
	if ra, ok := f.(io.ReaderAt); ok {
		return ra, nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, size))
	buf.Write(header)
	if _, err := io.Copy(buf, f); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

// wrapInFile builds the list returned for one artifact: a file node carrying
// the path and SHA-256 of the artifact as the root, with the decomposer's
// graph related to it as what the file was generated from.
func wrapInFile(graph *sbom.NodeList, path string, ra io.ReaderAt, size int64) (*sbom.NodeList, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(ra, 0, size)); err != nil {
		return nil, fmt.Errorf("hashing %q: %w", path, err)
	}

	file := &sbom.Node{
		Id:       uuid.NewString(),
		Type:     sbom.Node_FILE,
		Name:     path,
		FileName: path,
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): hex.EncodeToString(h.Sum(nil)),
		},
	}
	nl := sbom.NewNodeList()
	nl.AddRootNode(file)
	if err := nl.RelateNodeListAtID(graph, file.GetId(), sbom.Edge_generatedFrom); err != nil {
		return nil, fmt.Errorf("relating artifact graph to %q: %w", path, err)
	}
	return nl, nil
}

// skipMatcher compiles skip patterns into a matcher, or nil for none.
func skipMatcher(patterns []string) gitignore.Matcher {
	if len(patterns) == 0 {
		return nil
	}
	parsed := make([]gitignore.Pattern, 0, len(patterns))
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		parsed = append(parsed, gitignore.ParsePattern(p, nil))
	}
	return gitignore.NewMatcher(parsed)
}

// regularFiles lists every regular file in fsys, in lexical order, leaving
// out what skip matches: a matching directory is pruned without being
// entered. Symlinks are not followed: a link to an artifact is not the
// artifact.
func regularFiles(fsys fs.FS, skip gitignore.Matcher) ([]string, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		if skip != nil && skip.Match(strings.Split(path, "/"), d.IsDir()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

// RegisterDecomposer adds a decomposer to the unpacker, keyed by its name.
// The decomposer must implement the artifact Decomposer interface; others
// are ignored, since the Unpacker interface leaves no way to report them.
func (u *Unpacker) RegisterDecomposer(d api.Decomposer) {
	ad, ok := d.(Decomposer)
	if !ok {
		return
	}
	u.decomposers[ad.Name()] = ad
}

// UnregisterDecomposer removes a decomposer from the unpacker.
func (u *Unpacker) UnregisterDecomposer(d api.Decomposer) {
	if ad, ok := d.(Decomposer); ok {
		delete(u.decomposers, ad.Name())
	}
}

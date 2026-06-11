// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

// tarFS is a read-only fs.FS over an uncompressed tar file. The tar is
// indexed once — recording each entry's header and the offset of its data
// in the backing file — and file contents are then served lazily through an
// io.ReaderAt, so opening a squashed container filesystem never loads it
// into memory.
//
// Symlinks are resolved on access (with a hop budget, like the OS does) and
// hard links alias their target's data. Directories not explicitly present
// in the tar are synthesized from the paths of their children.
type tarFS struct {
	ra      io.ReaderAt
	entries map[string]*tarEntry
	// children lists the sorted child names of each directory, including
	// synthesized parents. The root directory is "." per fs.FS convention.
	children map[string][]string
}

type tarEntry struct {
	hdr    *tar.Header
	offset int64 // start of the entry's data in the backing file
}

var (
	_ fs.FS        = (*tarFS)(nil)
	_ fs.StatFS    = (*tarFS)(nil)
	_ fs.ReadDirFS = (*tarFS)(nil)
)

// newTarFS indexes the tar held by r. The reader must be positioned at the
// start of the archive and ra must read the same bytes.
func newTarFS(r io.Reader, ra io.ReaderAt) (*tarFS, error) {
	tfs := &tarFS{
		ra:       ra,
		entries:  map[string]*tarEntry{},
		children: map[string][]string{},
	}

	counter := &countingReader{r: r}
	tr := tar.NewReader(counter)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("indexing tar: %w", err)
		}

		name := path.Clean(strings.TrimPrefix(hdr.Name, "/"))
		if name == "." || !fs.ValidPath(name) {
			continue
		}

		// After Next() returns, the underlying reader sits exactly at the
		// start of the entry's data, so the byte counter is the offset.
		tfs.entries[name] = &tarEntry{hdr: hdr, offset: counter.n}
		tfs.addPath(name)
	}

	for dir := range tfs.children {
		sort.Strings(tfs.children[dir])
	}
	return tfs, nil
}

// addPath registers name under its parent directory and synthesizes any
// missing ancestor directories.
func (t *tarFS) addPath(name string) {
	for name != "." {
		parent := path.Dir(name)
		base := path.Base(name)
		if slices.Contains(t.children[parent], base) {
			return
		}
		t.children[parent] = append(t.children[parent], base)
		name = parent
	}
}

// countingReader tracks how many bytes have been consumed from r.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// maxLinkDepth bounds symlink resolution, mirroring the kernel's ELOOP
// behavior.
const maxLinkDepth = 40

// resolve follows symlinks in every component of name and returns the
// canonical path. Missing paths resolve to themselves — existence is the
// caller's concern — but unresolvable links exhaust the depth budget.
func (t *tarFS) resolve(name string, depth int) (string, error) {
	if depth <= 0 {
		return "", fmt.Errorf("too many levels of symbolic links")
	}

	resolved := "."
	parts := strings.Split(name, "/")
	for i, part := range parts {
		resolved = path.Join(resolved, part)
		e := t.entries[resolved]
		if e == nil || e.hdr.Typeflag != tar.TypeSymlink {
			continue
		}

		target := e.hdr.Linkname
		if path.IsAbs(target) {
			target = path.Clean(strings.TrimPrefix(target, "/"))
		} else {
			//nolint:gosec // G305: not an extraction; the result is a map key validated below
			target = path.Join(path.Dir(resolved), target)
		}
		if !fs.ValidPath(target) {
			return "", fmt.Errorf("symlink %q escapes the filesystem", resolved)
		}
		// Re-resolve the substituted prefix plus the remaining components.
		rest := append([]string{target}, parts[i+1:]...)
		return t.resolve(path.Join(rest...), depth-1)
	}
	return resolved, nil
}

// lookup resolves name and returns its entry. Implicit directories return a
// synthesized entry; missing paths return fs.ErrNotExist.
func (t *tarFS) lookup(op, name string) (string, *tarEntry, error) {
	if !fs.ValidPath(name) {
		return "", nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	resolved, err := t.resolve(name, maxLinkDepth)
	if err != nil {
		return "", nil, &fs.PathError{Op: op, Path: name, Err: err}
	}

	if e := t.entries[resolved]; e != nil {
		// Hard links alias another entry's data.
		if e.hdr.Typeflag == tar.TypeLink {
			target := path.Clean(strings.TrimPrefix(e.hdr.Linkname, "/"))
			if te := t.entries[target]; te != nil {
				return resolved, te, nil
			}
		}
		return resolved, e, nil
	}

	// Synthesize implicit directories (and the root).
	if _, ok := t.children[resolved]; ok || resolved == "." {
		return resolved, &tarEntry{hdr: &tar.Header{
			Name:     resolved,
			Typeflag: tar.TypeDir,
			Mode:     0o755,
			ModTime:  time.Unix(0, 0),
		}}, nil
	}

	return "", nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
}

// Open implements fs.FS.
func (t *tarFS) Open(name string) (fs.File, error) {
	resolved, e, err := t.lookup("open", name)
	if err != nil {
		return nil, err
	}

	switch e.hdr.Typeflag {
	case tar.TypeDir:
		entries, err := t.ReadDir(resolved)
		if err != nil {
			return nil, err
		}
		return &tarDir{info: e.hdr.FileInfo(), entries: entries}, nil
	default:
		return &tarFile{
			info: e.hdr.FileInfo(),
			r:    io.NewSectionReader(t.ra, e.offset, e.hdr.Size),
		}, nil
	}
}

// Stat implements fs.StatFS. Like os.Stat, it follows symlinks.
func (t *tarFS) Stat(name string) (fs.FileInfo, error) {
	_, e, err := t.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	return e.hdr.FileInfo(), nil
}

// ReadDir implements fs.ReadDirFS.
func (t *tarFS) ReadDir(name string) ([]fs.DirEntry, error) {
	resolved, e, err := t.lookup("readdir", name)
	if err != nil {
		return nil, err
	}
	if !e.hdr.FileInfo().IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}

	names := t.children[resolved]
	entries := make([]fs.DirEntry, 0, len(names))
	for _, child := range names {
		ce := t.entries[path.Join(resolved, child)]
		if ce == nil {
			// Implicit directory.
			entries = append(entries, fs.FileInfoToDirEntry(&dirInfo{name: child}))
			continue
		}
		info := ce.hdr.FileInfo()
		entries = append(entries, fs.FileInfoToDirEntry(renamedInfo{FileInfo: info, name: child}))
	}
	return entries, nil
}

// tarFile is an open regular file backed by a section of the tar.
type tarFile struct {
	info fs.FileInfo
	r    *io.SectionReader
}

func (f *tarFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *tarFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *tarFile) Close() error               { return nil }

// tarDir is an open directory handle supporting ReadDir.
type tarDir struct {
	info    fs.FileInfo
	entries []fs.DirEntry
	pos     int
}

func (d *tarDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *tarDir) Close() error               { return nil }
func (d *tarDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.Name(), Err: errors.New("is a directory")}
}

func (d *tarDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		out := d.entries[d.pos:]
		d.pos = len(d.entries)
		return out, nil
	}
	if d.pos >= len(d.entries) {
		return nil, io.EOF
	}
	end := min(d.pos+n, len(d.entries))
	out := d.entries[d.pos:end]
	d.pos = end
	return out, nil
}

// renamedInfo overrides a FileInfo's name. Tar headers carry full paths in
// some archives; directory listings must present base names.
type renamedInfo struct {
	fs.FileInfo
	name string
}

func (r renamedInfo) Name() string { return r.name }

// dirInfo is the FileInfo of a synthesized implicit directory.
type dirInfo struct {
	name string
}

func (d *dirInfo) Name() string       { return d.name }
func (d *dirInfo) Size() int64        { return 0 }
func (d *dirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }
func (d *dirInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (d *dirInfo) IsDir() bool        { return true }
func (d *dirInfo) Sys() any           { return nil }

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
)

// fileSource locates the per-package file lists of a dpkg database. The two
// layouts keep them in different places:
//
//   - classic: var/lib/dpkg/info/<name>[:<arch>].list holds the installed
//     paths and the matching .md5sums file holds digests for regular files.
//   - distroless: var/lib/dpkg/status.d/<name>.md5sums is all there is; the
//     image ships no info directory, so the file list comes from the digests
//     file alone.
type fileSource struct {
	source    fs.FS
	infoDir   string // classic layout; "" when the DB is a status.d dir
	statusDir string // distroless layout; "" when the DB is a status file
}

// newFileSource builds a fileSource for the database found at dbPath. For a
// classic status file the info directory lives next to it (var/lib/dpkg/info);
// a directory database is the distroless status.d itself.
func newFileSource(source fs.FS, dbPath string, isDir bool) *fileSource {
	if isDir {
		return &fileSource{source: source, statusDir: dbPath}
	}
	return &fileSource{source: source, infoDir: path.Join(path.Dir(dbPath), "info")}
}

// fileEntry is one file installed by a package: its absolute path and, when
// the database records one, its MD5 digest.
type fileEntry struct {
	path string
	md5  string
}

// addPackageFiles expands the file list owned by p and relates each file to
// the package node via a "contains" edge. Packages without file data (e.g.
// virtual packages, or stanzas whose companion files are missing) add
// nothing; that is not an error.
func (f *fileSource) addPackageFiles(nl *sbom.NodeList, p *dpkgPackage, packageID string) error {
	entries, err := f.packageFiles(p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		node := &sbom.Node{
			Id:       uuid.NewString(),
			Type:     sbom.Node_FILE,
			Name:     e.path,
			FileName: e.path,
		}
		if e.md5 != "" {
			node.Hashes = map[int32]string{
				int32(sbom.HashAlgorithm_MD5): e.md5,
			}
		}
		if err := nl.RelateNodeAtID(node, packageID, sbom.Edge_contains); err != nil {
			return err
		}
	}
	return nil
}

// packageFiles returns the files installed by p according to the layout this
// fileSource was built for.
func (f *fileSource) packageFiles(p *dpkgPackage) ([]fileEntry, error) {
	if f.statusDir != "" {
		return f.distrolessFiles(p)
	}
	return f.classicFiles(p)
}

// classicFiles assembles the file list from the dpkg info directory: paths
// come from the .list file and digests from the matching .md5sums file.
// Multi-arch packages register under "<name>:<arch>", others under "<name>";
// we probe the arch-qualified name first since it is the more specific one.
func (f *fileSource) classicFiles(p *dpkgPackage) ([]fileEntry, error) {
	basenames := []string{p.Name}
	if p.Architecture != "" && p.Architecture != "all" {
		basenames = []string{p.Name + ":" + p.Architecture, p.Name}
	}

	for _, base := range basenames {
		paths, err := f.readList(path.Join(f.infoDir, base+".list"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}

		sums, err := f.readMD5Sums(path.Join(f.infoDir, base+".md5sums"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}

		// The .list format carries no file-type marker, but directories
		// always appear as the parent of other entries in the same list, so
		// anything that prefixes another entry is a directory and skipped.
		parents := map[string]bool{}
		for _, fp := range paths {
			for d := path.Dir(fp); d != "/" && d != "."; d = path.Dir(d) {
				parents[d] = true
			}
		}

		entries := make([]fileEntry, 0, len(paths))
		for _, fp := range paths {
			// The root entry "/." is dpkg bookkeeping, not package content.
			if fp == "/." || parents[fp] {
				continue
			}
			// md5sums paths carry no leading slash; .list paths do.
			entries = append(entries, fileEntry{
				path: fp,
				md5:  sums[strings.TrimPrefix(fp, "/")],
			})
		}
		return entries, nil
	}
	return nil, nil
}

// distrolessFiles assembles the file list from the package's .md5sums file
// in status.d. Only regular files appear there (directories and symlinks
// carry no digest), so every entry comes with its hash.
func (f *fileSource) distrolessFiles(p *dpkgPackage) ([]fileEntry, error) {
	sums, err := f.readMD5Sums(path.Join(f.statusDir, p.Name+".md5sums"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	entries := make([]fileEntry, 0, len(sums))
	for fp, sum := range sums {
		entries = append(entries, fileEntry{path: "/" + fp, md5: sum})
	}
	return entries, nil
}

// readList reads a dpkg .list file: one absolute installed path per line.
func (f *fileSource) readList(p string) ([]string, error) {
	file, err := f.source.Open(p)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck // read-only file

	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			paths = append(paths, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %q: %w", p, err)
	}
	return paths, nil
}

// readMD5Sums reads a dpkg .md5sums file and returns path → digest. Lines
// are "<32 hex chars>  <path>" with the path relative to the filesystem
// root; paths may contain spaces, so only the first separator splits.
func (f *fileSource) readMD5Sums(p string) (map[string]string, error) {
	file, err := f.source.Open(p)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck // read-only file

	return parseMD5Sums(file)
}

func parseMD5Sums(r io.Reader) (map[string]string, error) {
	sums := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		hash, fp, ok := strings.Cut(scanner.Text(), "  ")
		if !ok || hash == "" || fp == "" {
			continue
		}
		sums[fp] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sums, nil
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package deb implements a SystemDecomposer that reads the installed-package
// database used by dpkg-based distributions (Debian, Ubuntu, ...) and by
// distroless images, which ship the same database split into per-package
// files.
package deb

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system/internal/osrelease"
)

// dpkgDBLocations are paths inside a system filesystem where an installed
// dpkg database may live. The classic layout is a single status file; the
// distroless layout is a directory of per-package stanzas.
var dpkgDBLocations = []string{
	"var/lib/dpkg/status",   // file: Debian, Ubuntu, ...
	"var/lib/dpkg/status.d", // directory: distroless images
}

var _ api.Decomposer = (*Decomposer)(nil)

// New returns a ready-to-use dpkg decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads the dpkg database from a system filesystem and emits a
// protobom NodeList of the installed packages.
type Decomposer struct{}

// Options configures the dpkg decomposer.
type Options struct {
	// DBPaths overrides the default search locations for the dpkg database.
	// Paths are relative to the FS root; each may point to a status file or
	// to a status.d-style directory.
	DBPaths []string
}

var defaultOptions = Options{}

// DefaultOptions returns the driver-level options used when none are set on
// DecomposerOptions.
func (d *Decomposer) DefaultOptions() any { return defaultOptions }

// Requirements returns the decomposer's runtime requirements. The dpkg
// database is plain text, so there are none.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// Extract opens opts.WorkDir as the system root and runs the FS-aware
// extractor against it. This lets the decomposer satisfy api.Decomposer for
// callers that work with on-disk paths; the SystemPackages unpacker calls
// ExtractFromFS directly so it can pass in non-OS filesystems too.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("dpkg decomposer needs a WorkDir to use as the system root")
	}
	return d.ExtractFromFS(os.DirFS(opts.WorkDir), opts)
}

// ExtractFromFS reads the dpkg database from source and returns the
// installed packages as a NodeList. Returns (nil, nil) when no dpkg database
// is present in the filesystem — dpkg is not the only system-package format
// we support and its absence is not an error.
func (d *Decomposer) ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	dOpts := d.getOptions(opts)
	locations := dOpts.DBPaths
	if len(locations) == 0 {
		locations = dpkgDBLocations
	}

	pkgs, dbPath, isDir, err := readDpkgDB(source, locations)
	if err != nil {
		return nil, fmt.Errorf("reading dpkg database: %w", err)
	}
	if pkgs == nil {
		return nil, nil
	}

	// os-release feeds the purl namespace and the distro= qualifier. If it's
	// missing we still emit purls, just without distro information.
	osr, err := osrelease.Read(source)
	if err != nil {
		return nil, fmt.Errorf("reading os-release: %w", err)
	}

	// The file lists live next to the database, in layout-specific places,
	// so the fileSource needs to know where the DB was found.
	var fsrc *fileSource
	if opts != nil && opts.IncludeFiles {
		fsrc = newFileSource(source, dbPath, isDir)
	}

	return packagesToNodeList(source, pkgs, osr, fsrc)
}

// readDpkgDB looks for the first dpkg database that exists in source at any
// of the given locations and parses it, reporting where it was found and
// whether it is a status.d-style directory of single-stanza files (as
// opposed to the classic status file). When no database is found, returns a
// nil slice; a found-but-empty database returns a non-nil empty slice.
func readDpkgDB(source fs.FS, locations []string) (pkgs []*dpkgPackage, dbPath string, isDir bool, err error) {
	for _, loc := range locations {
		info, err := fs.Stat(source, loc)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, "", false, fmt.Errorf("checking %q: %w", loc, err)
		}
		if info.IsDir() {
			pkgs, err = readStatusDir(source, loc)
		} else {
			pkgs, err = readStatusFile(source, loc)
		}
		return pkgs, loc, info.IsDir(), err
	}
	return nil, "", false, nil
}

// readStatusFile parses a classic single-file dpkg status database.
func readStatusFile(source fs.FS, p string) ([]*dpkgPackage, error) {
	f, err := source.Open(p)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", p, err)
	}
	defer f.Close() //nolint:errcheck // read-only file

	pkgs, err := parseStatus(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", p, err)
	}
	if pkgs == nil {
		pkgs = []*dpkgPackage{}
	}
	return pkgs, nil
}

// readStatusDir parses a distroless status.d directory where each file holds
// the control stanza of one package. The *.md5sums companions hold the
// package file digests and are skipped here.
func readStatusDir(source fs.FS, dir string) ([]*dpkgPackage, error) {
	entries, err := fs.ReadDir(source, dir)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", dir, err)
	}

	pkgs := []*dpkgPackage{}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".md5sums") {
			continue
		}
		filePkgs, err := readStatusFile(source, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, filePkgs...)
	}
	return pkgs, nil
}

// packagesToNodeList converts dpkg database entries into a protobom
// NodeList. Each installed package becomes a root node identified by its
// pkg:deb purl; stanzas for removed-but-not-purged packages are skipped.
// Licenses are read from each package's Debian copyright file in source.
// When fsrc is non-nil, each package's file list is also emitted as child
// Node_FILE nodes related via a "contains" edge.
func packagesToNodeList(source fs.FS, pkgs []*dpkgPackage, osr osrelease.Data, fsrc *fileSource) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	for _, p := range pkgs {
		if !p.Installed() {
			continue
		}
		node := &sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    p.Name,
			Version: p.Version,
			Summary: p.Summary,
			UrlHome: p.Homepage,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): debPurl(p, osr),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		licenses, concluded := packageLicenses(source, p.Name)
		node.Licenses = licenses
		node.LicenseConcluded = concluded
		if p.Maintainer != "" {
			// Maintainers are mostly teams (e.g. "Debian GNU Libc
			// Maintainers"), so flag them as orgs like we do for RPM vendors.
			node.Suppliers = []*sbom.Person{{
				Name: p.Maintainer, Email: p.Email, IsOrg: true,
			}}
		}
		nl.AddRootNode(node)

		if fsrc != nil {
			if err := fsrc.addPackageFiles(nl, p, node.GetId()); err != nil {
				return nil, fmt.Errorf("expanding files for %q: %w", p.Name, err)
			}
		}
	}
	return nl, nil
}

// debPurl builds a pkg:deb purl for a single dpkg package per the purl-spec
// deb definition: namespace is the lowercased distro id (e.g. "debian"),
// version is the complete Debian version (the epoch travels inside it), and
// qualifiers include arch, distro (id-version_id), and upstream (the source
// package, with its version when the stanza carries one). Qualifiers are
// sorted alphabetically and percent-encoded.
//
//	pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11
func debPurl(p *dpkgPackage, osr osrelease.Data) string {
	var b strings.Builder
	b.WriteString("pkg:deb/")
	if ns := osr.Namespace(); ns != "" {
		b.WriteString(ns)
		b.WriteByte('/')
	}
	b.WriteString(strings.ToLower(p.Name))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}

	q := url.Values{}
	if p.Architecture != "" {
		q.Set("arch", strings.ToLower(p.Architecture))
	}
	if d := osr.Distro(); d != "" {
		q.Set("distro", d)
	}
	if p.Source != "" {
		upstream := p.Source
		if p.SourceVersion != "" {
			upstream += "@" + p.SourceVersion
		}
		q.Set("upstream", upstream)
	}
	if enc := q.Encode(); enc != "" {
		b.WriteByte('?')
		b.WriteString(enc)
	}
	return b.String()
}

// getOptions extracts dpkg-specific options from DecomposerOptions, falling
// back to the package defaults.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	return &defaultOptions
}

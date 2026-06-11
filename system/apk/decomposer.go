// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package apk implements a SystemDecomposer that reads the installed-package
// database used by apk-based distributions (Alpine, Wolfi, ...).
package apk

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/license"
	"github.com/carabiner-dev/unpack/system/internal/osrelease"
)

// apkDBLocations are paths inside a system filesystem where an installed
// apk database may live.
var apkDBLocations = []string{
	"lib/apk/db/installed",
	"usr/lib/apk/db/installed", // usr-merged layouts
}

var _ api.Decomposer = (*Decomposer)(nil)

// New returns a ready-to-use apk decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads the apk database from a system filesystem and emits a
// protobom NodeList of the installed packages.
type Decomposer struct{}

// Options configures the apk decomposer.
type Options struct {
	// DBPaths overrides the default search locations for the apk installed
	// database. Paths are relative to the FS root.
	DBPaths []string
}

var defaultOptions = Options{}

// DefaultOptions returns the driver-level options used when none are set on
// DecomposerOptions.
func (d *Decomposer) DefaultOptions() any { return defaultOptions }

// Requirements returns the decomposer's runtime requirements. The apk
// database is plain text, so there are none.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// Extract opens opts.WorkDir as the system root and runs the FS-aware
// extractor against it. This lets the decomposer satisfy api.Decomposer for
// callers that work with on-disk paths; the SystemPackages unpacker calls
// ExtractFromFS directly so it can pass in non-OS filesystems too.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("apk decomposer needs a WorkDir to use as the system root")
	}
	return d.ExtractFromFS(os.DirFS(opts.WorkDir), opts)
}

// ExtractFromFS reads the apk database from source and returns the installed
// packages as a NodeList. Returns (nil, nil) when no apk database is present
// in the filesystem — apk is not the only system-package format we support
// and its absence is not an error.
func (d *Decomposer) ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	dOpts := d.getOptions(opts)
	locations := dOpts.DBPaths
	if len(locations) == 0 {
		locations = apkDBLocations
	}

	pkgs, err := readApkDB(source, locations)
	if err != nil {
		return nil, fmt.Errorf("reading apk database: %w", err)
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

	return packagesToNodeList(pkgs, osr, opts != nil && opts.IncludeFiles)
}

// readApkDB looks for the first apk installed database that exists in
// source at any of the given locations and parses it. When no database is
// found, returns a nil slice; a found-but-empty database returns a non-nil
// empty slice.
func readApkDB(source fs.FS, locations []string) ([]*apkPackage, error) {
	for _, loc := range locations {
		f, err := source.Open(loc)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("opening %q: %w", loc, err)
		}
		defer f.Close() //nolint:errcheck // read-only file

		pkgs, err := parseInstalled(f)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", loc, err)
		}
		if pkgs == nil {
			pkgs = []*apkPackage{}
		}
		return pkgs, nil
	}
	return nil, nil
}

// packagesToNodeList converts apk database entries into a protobom
// NodeList. Each package becomes a root node identified by its pkg:apk
// purl. When includeFiles is true, each package's file records are also
// emitted as child Node_FILE nodes related via a "contains" edge.
func packagesToNodeList(pkgs []*apkPackage, osr osrelease.Data, includeFiles bool) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	for _, p := range pkgs {
		node := &sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    p.Name,
			Version: p.Version,
			Summary: p.Description,
			UrlHome: p.URL,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): apkPurl(p, osr),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		if p.License != "" {
			// Alpine's L: field already carries SPDX expressions for the
			// most part; Normalize fixes stray aliases and leaves
			// expressions it doesn't know unchanged.
			node.Licenses = []string{license.Normalize(p.License, "")}
		}
		if p.Maintainer != "" {
			node.Suppliers = []*sbom.Person{{
				Name: p.Maintainer, Email: p.Email,
			}}
		}
		if p.Checksum != "" {
			// The C: field is the SHA1 identity checksum apk uses to
			// address the package.
			node.Hashes = map[int32]string{
				int32(sbom.HashAlgorithm_SHA1): p.Checksum,
			}
		}
		nl.AddRootNode(node)

		if includeFiles {
			if err := addPackageFiles(nl, p, node.GetId()); err != nil {
				return nil, fmt.Errorf("expanding files for %q: %w", p.Name, err)
			}
		}
	}
	return nl, nil
}

// addPackageFiles emits the file records owned by p and relates each one to
// the package node via a "contains" edge. Regular files get their SHA1 from
// the database's Z: records; special files carry no digest.
func addPackageFiles(nl *sbom.NodeList, p *apkPackage, packageID string) error {
	for _, f := range p.Files {
		node := &sbom.Node{
			Id:       uuid.NewString(),
			Type:     sbom.Node_FILE,
			Name:     f.Path,
			FileName: f.Path,
		}
		if f.SHA1 != "" {
			node.Hashes = map[int32]string{
				int32(sbom.HashAlgorithm_SHA1): f.SHA1,
			}
		}
		if err := nl.RelateNodeAtID(node, packageID, sbom.Edge_contains); err != nil {
			return err
		}
	}
	return nil
}

// apkPurl builds a pkg:apk purl for a single apk package per the purl-spec
// apk definition: namespace is the lowercased distro id (e.g. "alpine"),
// and qualifiers include arch, distro (id-version_id), and upstream (the
// origin/source package when it differs from the package name). Qualifiers
// are sorted alphabetically and percent-encoded.
//
//	pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.24.0
func apkPurl(p *apkPackage, osr osrelease.Data) string {
	var b strings.Builder
	b.WriteString("pkg:apk/")
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
	if p.Arch != "" {
		q.Set("arch", strings.ToLower(p.Arch))
	}
	if d := osr.Distro(); d != "" {
		q.Set("distro", d)
	}
	if p.Origin != "" && p.Origin != p.Name {
		q.Set("upstream", p.Origin)
	}
	if enc := q.Encode(); enc != "" {
		b.WriteByte('?')
		b.WriteString(enc)
	}
	return b.String()
}

// getOptions extracts apk-specific options from DecomposerOptions, falling
// back to the package defaults.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	return &defaultOptions
}

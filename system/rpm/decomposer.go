// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package rpm implements a SystemDecomposer that reads the installed-package
// database used by RPM-based distributions (RHEL, Fedora, openSUSE, ...).
package rpm

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	"github.com/google/uuid"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// rpmDBLocations are paths inside a system filesystem where an installed RPM
// database may live. Ordered most-modern-first so newer formats win when more
// than one is present.
var rpmDBLocations = []string{
	"var/lib/rpm/rpmdb.sqlite",          // sqlite
	"var/lib/rpm/Packages.db",           // ndb
	"var/lib/rpm/Packages",              // bdb
	"usr/lib/sysimage/rpm/rpmdb.sqlite", // sqlite (Fedora 36+ image-mode)
	"usr/lib/sysimage/rpm/Packages.db",  // ndb
	"usr/lib/sysimage/rpm/Packages",     // bdb
}

// virtualPackages are entries in the RPM database that don't represent real
// software and are filtered out of the resulting NodeList.
var virtualPackages = map[string]bool{
	"gpg-pubkey": true,
}

var _ api.Decomposer = (*Decomposer)(nil)

// New returns a ready-to-use RPM decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads the RPM database from a system filesystem and emits a
// protobom NodeList of the installed packages.
type Decomposer struct{}

// Options configures the RPM decomposer.
type Options struct {
	// DBPaths overrides the default search locations for the RPM database.
	// Paths are relative to the FS root.
	DBPaths []string
}

var defaultOptions = Options{}

// DefaultOptions returns the driver-level options used when none are set on
// DecomposerOptions.
func (d *Decomposer) DefaultOptions() any { return defaultOptions }

// Requirements returns the decomposer's runtime requirements. The RPM
// decomposer uses pure-Go libraries and has none.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement { return nil }

// Extract opens opts.WorkDir as the system root and runs the FS-aware
// extractor against it. This lets the decomposer satisfy api.Decomposer for
// callers that work with on-disk paths; the SystemPackages unpacker calls
// ExtractFromFS directly so it can pass in non-OS filesystems too.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("rpm decomposer needs a WorkDir to use as the system root")
	}
	return d.ExtractFromFS(os.DirFS(opts.WorkDir), opts)
}

// ExtractFromFS reads the RPM database from source and returns the installed
// packages as a NodeList. Returns (nil, nil) when no RPM database is present
// in the filesystem — RPM is not the only system-package format we support
// and its absence is not an error.
func (d *Decomposer) ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	dOpts := d.getOptions(opts)
	locations := dOpts.DBPaths
	if len(locations) == 0 {
		locations = rpmDBLocations
	}

	dbPath, cleanup, err := stageRpmDB(source, locations)
	if err != nil {
		return nil, fmt.Errorf("staging rpm database: %w", err)
	}
	if dbPath == "" {
		return nil, nil
	}
	defer cleanup() //nolint:errcheck // best-effort temp dir cleanup

	db, err := rpmdb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening rpm database: %w", err)
	}
	defer db.Close() //nolint:errcheck

	pkgs, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("listing rpm packages: %w", err)
	}

	return packagesToNodeList(pkgs), nil
}

// stageRpmDB looks for the first RPM database that exists in source at any of
// the given locations and copies it to a temporary on-disk file. go-rpmdb
// (especially the SQLite driver) needs an OS file path to operate on, so the
// DB has to live on a real filesystem during the read.
//
// Returns the staged path and a cleanup function that removes the staging
// directory. When no database is found, returns ("", noop, nil).
func stageRpmDB(source fs.FS, locations []string) (string, func() error, error) {
	noop := func() error { return nil }
	for _, loc := range locations {
		f, err := source.Open(loc)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", noop, fmt.Errorf("opening %q: %w", loc, err)
		}

		dstPath, cleanup, copyErr := copyToTemp(f, loc)
		if cerr := f.Close(); cerr != nil && copyErr == nil {
			copyErr = fmt.Errorf("closing source db: %w", cerr)
		}
		if copyErr != nil {
			cleanup() //nolint:errcheck
			return "", noop, copyErr
		}
		return dstPath, cleanup, nil
	}
	return "", noop, nil
}

// copyToTemp streams f into a fresh temp directory and returns the staged
// path plus a cleanup function. Errors arrange for the temp dir to be
// removed before returning.
func copyToTemp(f fs.File, srcPath string) (string, func() error, error) {
	tmpDir, err := os.MkdirTemp("", "unpack-rpmdb-")
	if err != nil {
		return "", func() error { return nil }, fmt.Errorf("creating temp dir: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(tmpDir) }

	dstPath := path.Join(tmpDir, path.Base(srcPath))
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", cleanup, fmt.Errorf("creating staging file: %w", err)
	}
	if _, err := io.Copy(dst, f); err != nil {
		dst.Close() //nolint:errcheck
		return "", cleanup, fmt.Errorf("copying rpm database: %w", err)
	}
	if err := dst.Close(); err != nil {
		return "", cleanup, fmt.Errorf("closing staged db: %w", err)
	}
	return dstPath, cleanup, nil
}

// packagesToNodeList converts go-rpmdb package entries into a protobom
// NodeList. Each package becomes a root node identified by its pkg:rpm purl.
func packagesToNodeList(pkgs []*rpmdb.PackageInfo) *sbom.NodeList {
	nl := sbom.NewNodeList()
	for _, p := range pkgs {
		if virtualPackages[p.Name] {
			continue
		}
		node := &sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    p.Name,
			Version: versionRelease(p),
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): rpmPurl(p),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		if p.License != "" {
			// Most RPM packages don't carry SPDX-valid license names, but
			// downstream consumers can still normalize them.
			node.Licenses = []string{p.License}
		}
		nl.AddRootNode(node)
	}
	return nl
}

// versionRelease combines the RPM version and release fields the way RPM
// itself addresses a package on disk: "version-release".
func versionRelease(p *rpmdb.PackageInfo) string {
	if p.Release == "" {
		return p.Version
	}
	return fmt.Sprintf("%s-%s", p.Version, p.Release)
}

// rpmPurl builds a pkg:rpm purl for a single RPM package. The namespace
// (vendor/distro) is left empty until we add /etc/os-release detection.
func rpmPurl(p *rpmdb.PackageInfo) string {
	purl := fmt.Sprintf("pkg:rpm/%s@%s", p.Name, purlVersion(p))
	if p.Arch != "" {
		purl = fmt.Sprintf("%s?arch=%s", purl, p.Arch)
	}
	return purl
}

// purlVersion encodes the package version for a purl, including the epoch
// when it is non-zero. The purl-spec puts the epoch in front of the version
// separated by a colon.
func purlVersion(p *rpmdb.PackageInfo) string {
	v := versionRelease(p)
	if p.Epoch != nil && *p.Epoch > 0 {
		return fmt.Sprintf("%d:%s", *p.Epoch, v)
	}
	return v
}

// getOptions extracts RPM-specific options from DecomposerOptions, falling
// back to the package defaults.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	return &defaultOptions
}

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
	"strconv"
	"strings"

	"github.com/google/uuid"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system/internal/osrelease"
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

	// os-release feeds the purl namespace and the distro= qualifier. If it's
	// missing we still emit purls, just without distro information.
	osr, err := osrelease.Read(source)
	if err != nil {
		return nil, fmt.Errorf("reading os-release: %w", err)
	}

	return packagesToNodeList(pkgs, osr, opts != nil && opts.IncludeFiles)
}

// stageRpmDB looks for the first RPM database that exists in source at any of
// the given locations and copies it to a temporary on-disk file. go-rpmdb
// (especially the SQLite driver) needs an OS file path to operate on, so the
// DB has to live on a real filesystem during the read.
//
// Returns the staged path and a cleanup function that removes the staging
// directory. When no database is found, returns ("", noop, nil).
func stageRpmDB(source fs.FS, locations []string) (dbPath string, cleanup func() error, err error) {
	noop := func() error { return nil }
	for _, loc := range locations {
		f, openErr := source.Open(loc)
		if openErr != nil {
			if errors.Is(openErr, fs.ErrNotExist) {
				continue
			}
			return "", noop, fmt.Errorf("opening %q: %w", loc, openErr)
		}

		dstPath, dstCleanup, copyErr := copyToTemp(f, loc)
		if cerr := f.Close(); cerr != nil && copyErr == nil {
			copyErr = fmt.Errorf("closing source db: %w", cerr)
		}
		if copyErr != nil {
			//nolint:errcheck,gosec // cleanup is best-effort; we already have an error to surface
			dstCleanup()
			return "", noop, copyErr
		}
		return dstPath, dstCleanup, nil
	}
	return "", noop, nil
}

// copyToTemp streams f into a fresh temp directory and returns the staged
// path plus a cleanup function. Errors arrange for the temp dir to be
// removed before returning.
func copyToTemp(f fs.File, srcPath string) (dstPath string, cleanup func() error, err error) {
	tmpDir, err := os.MkdirTemp("", "unpack-rpmdb-")
	if err != nil {
		return "", func() error { return nil }, fmt.Errorf("creating temp dir: %w", err)
	}
	cleanup = func() error { return os.RemoveAll(tmpDir) }

	dstPath = path.Join(tmpDir, path.Base(srcPath))
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", cleanup, fmt.Errorf("creating staging file: %w", err)
	}
	if _, err := io.Copy(dst, f); err != nil {
		//nolint:errcheck,gosec // close is best-effort; we already have an error to surface
		dst.Close()
		return "", cleanup, fmt.Errorf("copying rpm database: %w", err)
	}
	if err := dst.Close(); err != nil {
		return "", cleanup, fmt.Errorf("closing staged db: %w", err)
	}
	return dstPath, cleanup, nil
}

// packagesToNodeList converts go-rpmdb package entries into a protobom
// NodeList. Each package becomes a root node identified by its pkg:rpm purl.
// When includeFiles is true, each package's file list is also emitted as
// child Node_FILE nodes related via a "contains" edge.
func packagesToNodeList(pkgs []*rpmdb.PackageInfo, osr osrelease.Data, includeFiles bool) (*sbom.NodeList, error) {
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
			Summary: p.Summary,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): rpmPurl(p, osr),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		if p.License != "" {
			// Most RPM packages don't carry SPDX-valid license names, but
			// downstream consumers can still normalize them.
			node.Licenses = []string{p.License}
		}
		if p.Vendor != "" {
			node.Suppliers = []*sbom.Person{{Name: p.Vendor, IsOrg: true}}
		}
		if p.SigMD5 != "" {
			// SigMD5 is the MD5 over the original .rpm envelope and is the
			// canonical identifier used by Red Hat's vulnerability and signature
			// feeds (e.g. clamav, OVAL).
			node.Hashes = map[int32]string{
				int32(sbom.HashAlgorithm_MD5): p.SigMD5,
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

// versionRelease combines the RPM version and release fields the way RPM
// itself addresses a package on disk: "version-release".
func versionRelease(p *rpmdb.PackageInfo) string {
	if p.Release == "" {
		return p.Version
	}
	return fmt.Sprintf("%s-%s", p.Version, p.Release)
}

// rpmPurl builds a pkg:rpm purl for a single RPM package per the purl-spec
// rpm-definition: namespace is the lowercased distro id (e.g. "fedora"),
// version is the combined version-release, and qualifiers include arch,
// epoch (when > 0), upstream (the source RPM), distro (id-version_id), and
// the Fedora modularity label when present.
//
// Assembly is delegated to packageurl-go so every component carries the
// canonical purl encoding: qualifiers come out sorted alphabetically and the
// characters the spec reserves get percent-encoded. That matters for RPM in
// particular because "+" (which the spec requires to be written "%2B") is
// common in upstream versions and modular release tags. Scanners match purls
// by string comparison, so a non-canonical encoding silently misses.
//
//	pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25
//	pkg:rpm/fedora/nodejs@14.21.3-1.module_f38%2B18119%2B78d34c93?arch=x86_64&distro=fedora-38
func rpmPurl(p *rpmdb.PackageInfo, osr osrelease.Data) string {
	q := map[string]string{}
	if p.Arch != "" {
		q["arch"] = strings.ToLower(p.Arch)
	}
	if p.Epoch != nil && *p.Epoch > 0 {
		q["epoch"] = strconv.Itoa(*p.Epoch)
	}
	if p.SourceRpm != "" {
		q["upstream"] = p.SourceRpm
	}
	if d := osr.Distro(); d != "" {
		q["distro"] = d
	}
	if p.Modularitylabel != "" {
		q["modularitylabel"] = p.Modularitylabel
	}

	// The name is passed through verbatim: RPM package names are
	// case-sensitive and packageurl-go does not case-fold them.
	return packageurl.NewPackageURL(
		packageurl.TypeRPM, osr.Namespace(), p.Name, versionRelease(p),
		packageurl.QualifiersFromMap(q), "",
	).ToString()
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

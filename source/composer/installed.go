// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/internal/logging"
)

// This file reads installed Composer environments: the installed.json a
// Composer install writes into its vendor directory, which is how a
// deployed PHP application or a container image says what it actually
// holds. The entries are the lockfile's own shape, so an installed
// environment reads like a lock found in place — with the project's
// composer.json next to the vendor directory supplying the root when it is
// there, and the graph's own shape supplying the roots when it is not.

// installedJSON is the file as Composer 2 writes it. Composer 1 wrote the
// bare package array instead.
type installedJSON struct {
	Packages []*ComposerPackage `json:"packages"`

	// DevPackageNames names the packages only development needs: the
	// installed counterpart of the lock's packages-dev partition.
	DevPackageNames []string `json:"dev-package-names"`
}

// ParseInstalledJSON reads an installed.json document, in either
// generation's shape, into the lock structure everything else builds from.
func ParseInstalledJSON(data []byte) (*ComposerLock, error) {
	parsed := &installedJSON{}
	if err := json.Unmarshal(data, parsed); err != nil || parsed.Packages == nil {
		// Composer 1 wrote the packages bare.
		var packages []*ComposerPackage
		if arrayErr := json.Unmarshal(data, &packages); arrayErr != nil {
			return nil, fmt.Errorf("parsing installed.json: %w", arrayErr)
		}
		parsed = &installedJSON{Packages: packages}
	}

	dev := map[string]bool{}
	for _, name := range parsed.DevPackageNames {
		dev[name] = true
	}

	lock := &ComposerLock{}
	for _, pkg := range parsed.Packages {
		if pkg.Name == "" {
			return nil, fmt.Errorf("installed.json holds a nameless package")
		}
		if dev[pkg.Name] {
			lock.PackagesDev = append(lock.PackagesDev, pkg)
		} else {
			lock.Packages = append(lock.Packages, pkg)
		}
	}
	return lock, nil
}

// ExtractInstalled reads every installed Composer environment on a
// filesystem and returns their merged graph, or (nil, nil) when the
// filesystem holds none.
func ExtractInstalled(fsys fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	locations := []string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory hides its own contents, nothing more.
			return nil //nolint:nilerr // deliberate: scan what is readable
		}
		if !d.IsDir() && d.Name() == "installed.json" && path.Base(path.Dir(p)) == "composer" {
			locations = append(locations, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(locations) == 0 {
		return nil, nil
	}
	sort.Strings(locations)

	merged := sbom.NewNodeList()
	for _, location := range locations {
		nl, err := extractVendor(fsys, location, opts)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", location, err)
		}
		merged.Add(nl)
	}
	return merged, nil
}

// extractVendor builds the graph of one vendor directory.
func extractVendor(fsys fs.FS, installedPath string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	data, err := fs.ReadFile(fsys, installedPath)
	if err != nil {
		return nil, err
	}
	lock, err := ParseInstalledJSON(data)
	if err != nil {
		return nil, err
	}

	// The project the vendor directory belongs to lives above it, and its
	// manifest names the root and the direct requirements: with it, an
	// installed environment reads exactly like a lock found in place.
	projectDir := path.Dir(path.Dir(path.Dir(installedPath)))
	if manifestData, err := fs.ReadFile(fsys, path.Join(projectDir, "composer.json")); err == nil {
		if manifest, err := ParseComposerJSON(manifestData); err == nil && manifest.Name != "" {
			return buildComposerTree(lock, manifest, opts, logging.Silent())
		}
	}
	return buildInstalledTree(lock, opts)
}

// buildInstalledTree builds the graph of a vendor directory with no
// manifest to walk from: every installed package is a node, the require
// tables are the edges, and whatever nothing here depends on is a root.
// A requirement is met by the package of its name, or by those standing
// in for it.
func buildInstalledTree(lock *ComposerLock, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	cb := &composerBuilder{
		opts:   opts,
		nl:     sbom.NewNodeList(),
		byName: map[string]*ComposerPackage{},
		nodes:  map[string]*sbom.Node{},
	}

	packages := append([]*ComposerPackage{}, lock.Packages...)
	if opts.IncludeDev {
		packages = append(packages, lock.PackagesDev...)
	}
	for _, pkg := range packages {
		cb.byName[pkg.Name] = pkg
	}
	// A requirement on a name with no package of its own is met by the
	// installed packages replacing or providing it, as in a lock.
	cb.standIns = indexStandIns(packages)

	// requirements lists what each package's requirements resolve to
	// among the installed packages, sorted and without the package
	// itself. A requirement nothing installed meets resolves to nothing:
	// a dev-only requirement with dev not asked for, or an incomplete
	// vendor tree.
	requirements := map[string][]string{}
	required := map[string]bool{}
	for _, pkg := range packages {
		node := cb.packageNode(pkg)
		cb.nodes[pkg.Name] = node

		targets := map[string]struct{}{}
		for name := range pkg.Require {
			if isPlatformRequirement(name) {
				continue
			}
			for _, target := range cb.resolve(name) {
				if target.Name != pkg.Name {
					targets[target.Name] = struct{}{}
				}
			}
		}
		names := make([]string, 0, len(targets))
		for name := range targets {
			names = append(names, name)
			required[name] = true
		}
		sort.Strings(names)
		requirements[pkg.Name] = names
	}

	// Roots first, then everything else, then the edges.
	for _, pkg := range packages {
		if !required[pkg.Name] {
			cb.nl.AddRootNode(cb.nodes[pkg.Name])
		} else {
			cb.nl.AddNode(cb.nodes[pkg.Name])
		}
	}
	for _, pkg := range packages {
		for _, name := range requirements[pkg.Name] {
			if err := cb.nl.RelateNodeAtID(cb.nodes[name], cb.nodes[pkg.Name].GetId(), sbom.Edge_dependsOn); err != nil {
				return nil, err
			}
		}
	}
	return cb.nl, nil
}

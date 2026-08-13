// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"path"
	"sort"
	"strconv"
	"strings"
)

// This file reads installed Python environments: the *.dist-info
// directories an installer writes into site-packages, one per installed
// distribution. This is how a container image or a virtualenv says what
// Python software it actually holds — no lockfile needed, and none may
// exist. Everything is read through an fs.FS, so a filesystem, an image
// layer or a test fixture all look the same.

// InstalledDistribution is one installed package, read from its dist-info.
type InstalledDistribution struct {
	// Name is normalized; the dist-info directory spells it however the
	// wheel did (PySocks-1.7.1.dist-info).
	Name    string
	Version string

	Summary        string
	RequiresPython string
	HomePage       string
	ProjectURLs    map[string]string

	// The three licence tiers, as METADATA states them; LicensesFromMetadata
	// of the node builder triages them.
	LicenseExpression string
	License           string
	Classifiers       []string

	// RequiresDist are the declared dependencies, raw PEP 508.
	RequiresDist []string

	// Installer names the tool that installed the package (the INSTALLER
	// file), and Requested says the install was asked for rather than
	// pulled in (the REQUESTED marker, PEP 376).
	Installer string
	Requested bool

	// DirectURL is the provenance of a package installed from a URL or a
	// repository rather than an index (direct_url.json, PEP 610).
	DirectURL *DirectURL

	// Files is the RECORD: every file the installation owns.
	Files []InstalledFile

	// Path is the dist-info directory, relative to the FS the environment
	// was read from.
	Path string
}

// DirectURL is a parsed direct_url.json.
type DirectURL struct {
	URL     string `json:"url"`
	VCSInfo struct {
		VCS               string `json:"vcs"`
		CommitID          string `json:"commit_id"`
		RequestedRevision string `json:"requested_revision"`
	} `json:"vcs_info"`
	DirInfo struct {
		Editable bool `json:"editable"`
	} `json:"dir_info"`
}

// InstalledFile is one RECORD entry.
type InstalledFile struct {
	// Path is relative to the site-packages directory (entries may climb
	// out of it: ../../../bin/pip).
	Path string

	// Algorithm and Digest are the recorded hash, the digest in the
	// urlsafe base64 RECORD states it in. Empty for the files an
	// installer rewrites, RECORD itself among them.
	Algorithm string
	Digest    string

	Size int64
}

// FindDistributions walks a filesystem and reads every installed
// distribution on it, wherever its site-packages lives: system interpreters,
// virtualenvs and --target directories all qualify. A distribution whose
// metadata cannot be read is skipped: one broken package should not hide an
// environment.
func FindDistributions(fsys fs.FS) ([]*InstalledDistribution, error) {
	var dists []*InstalledDistribution
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory hides its own contents, nothing more.
			return nil //nolint:nilerr // deliberate: scan what is readable
		}
		if !d.IsDir() || !strings.HasSuffix(p, ".dist-info") {
			return nil
		}
		dist, readErr := ReadDistribution(fsys, p)
		if readErr == nil {
			dists = append(dists, dist)
		}
		return fs.SkipDir
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(dists, func(i, j int) bool {
		if dists[i].Name != dists[j].Name {
			return dists[i].Name < dists[j].Name
		}
		return dists[i].Path < dists[j].Path
	})
	return dists, nil
}

// ReadDistribution reads one dist-info directory.
func ReadDistribution(fsys fs.FS, dir string) (*InstalledDistribution, error) {
	dist := &InstalledDistribution{Path: dir}
	if err := dist.readMetadata(fsys, path.Join(dir, "METADATA")); err != nil {
		return nil, err
	}

	// Everything after METADATA is optional: a bare dist-info still
	// describes an installed package.
	dist.Files = readRecord(fsys, path.Join(dir, "RECORD"))
	if data, err := fs.ReadFile(fsys, path.Join(dir, "INSTALLER")); err == nil {
		dist.Installer = strings.TrimSpace(string(data))
	}
	if _, err := fs.Stat(fsys, path.Join(dir, "REQUESTED")); err == nil {
		dist.Requested = true
	}
	if data, err := fs.ReadFile(fsys, path.Join(dir, "direct_url.json")); err == nil {
		directURL := &DirectURL{}
		if json.Unmarshal(data, directURL) == nil {
			dist.DirectURL = directURL
		}
	}
	return dist, nil
}

// readMetadata reads the core metadata file (an email-style header block;
// the body, holding the long description, is not read).
func (dist *InstalledDistribution) readMetadata(fsys fs.FS, p string) error {
	file, err := fsys.Open(p)
	if err != nil {
		return fmt.Errorf("a dist-info without METADATA: %w", err)
	}
	defer file.Close() //nolint:errcheck // read-only

	header, err := textproto.NewReader(bufio.NewReader(file)).ReadMIMEHeader()
	// ReadMIMEHeader returns io.EOF for a headers-only file, which a
	// METADATA with no description body is.
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading METADATA: %w", err)
	}

	dist.Name = NormalizeName(header.Get("Name"))
	if dist.Name == "" {
		return fmt.Errorf("METADATA names no distribution")
	}
	dist.Version = header.Get("Version")
	dist.Summary = header.Get("Summary")
	dist.RequiresPython = header.Get("Requires-Python")
	dist.LicenseExpression = header.Get("License-Expression")
	dist.License = header.Get("License")
	dist.Classifiers = header.Values("Classifier")
	dist.RequiresDist = header.Values("Requires-Dist")
	dist.HomePage = header.Get("Home-Page")

	for _, entry := range header.Values("Project-Url") {
		if label, url, found := strings.Cut(entry, ","); found {
			if dist.ProjectURLs == nil {
				dist.ProjectURLs = map[string]string{}
			}
			dist.ProjectURLs[strings.TrimSpace(label)] = strings.TrimSpace(url)
		}
	}
	return nil
}

// readRecord reads the RECORD file: CSV rows of path, hash and size. A
// missing or unreadable RECORD reads as no files, not as an error.
func readRecord(fsys fs.FS, p string) []InstalledFile {
	file, err := fsys.Open(p)
	if err != nil {
		return nil
	}
	defer file.Close() //nolint:errcheck // read-only

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	files := []InstalledFile{}
	for {
		row, err := reader.Read()
		if err != nil {
			return files
		}
		if len(row) < 1 || row[0] == "" {
			continue
		}
		entry := InstalledFile{Path: row[0]}
		if len(row) > 1 {
			entry.Algorithm, entry.Digest, _ = strings.Cut(row[1], "=")
		}
		if len(row) > 2 {
			if size, err := strconv.ParseInt(row[2], 10, 64); err == nil {
				entry.Size = size
			}
		}
		files = append(files, entry)
	}
}

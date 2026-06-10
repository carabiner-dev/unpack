// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package osrelease reads the systemd os-release file from a system
// filesystem. System-package decomposers use it to enrich package purls with
// the distribution's namespace and a distro= qualifier.
package osrelease

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"strings"
)

// paths are the locations where systemd's os-release file may live.
// Distributions are required to provide one of them; modern distros ship both
// (etc symlinks to usr) so order rarely matters.
var paths = []string{
	"etc/os-release",
	"usr/lib/os-release",
}

// Data holds the fields of the system's os-release file we use to enrich
// package purls. ID feeds the purl namespace; ID + VersionID feed the
// distro= qualifier.
type Data struct {
	ID        string // e.g. "fedora", "debian", "ubuntu", "alpine"
	VersionID string // e.g. "38", "12", "22.04"
}

// Namespace returns the purl namespace (the vendor, lowercased) or "" when
// the os-release ID is unknown.
func (o Data) Namespace() string {
	return strings.ToLower(o.ID)
}

// Distro returns the value for the purl distro= qualifier (e.g. "fedora-38",
// "debian-12") or "" when either component is missing.
func (o Data) Distro() string {
	if o.ID == "" || o.VersionID == "" {
		return ""
	}
	return strings.ToLower(o.ID) + "-" + o.VersionID
}

// Read reads the first os-release file found in source. A missing file is
// not an error — purls just get emitted without a namespace/distro.
func Read(source fs.FS) (Data, error) {
	for _, p := range paths {
		f, err := source.Open(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return Data{}, err
		}
		o, err := Parse(f)
		//nolint:errcheck,gosec // close is best-effort on a read-only file
		f.Close()
		if err != nil {
			return Data{}, err
		}
		return o, nil
	}
	return Data{}, nil
}

// Parse parses the shell-fragment format used by os-release. Each line is
// KEY=VALUE; VALUE may be optionally double- or single-quoted. We only
// extract the keys we care about.
func Parse(r io.Reader) (Data, error) {
	var out Data
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"'`)
		switch strings.TrimSpace(key) {
		case "ID":
			out.ID = value
		case "VERSION_ID":
			out.VersionID = value
		}
	}
	if err := scanner.Err(); err != nil {
		return Data{}, err
	}
	return out, nil
}

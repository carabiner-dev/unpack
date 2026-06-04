// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rpm

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"strings"
)

// osReleasePaths are the locations where systemd's os-release file may live.
// Distributions are required to provide one of them; modern distros ship both
// (etc symlinks to usr) so order rarely matters.
var osReleasePaths = []string{
	"etc/os-release",
	"usr/lib/os-release",
}

// osRelease holds the fields of the system's os-release file we use to enrich
// pkg:rpm purls. ID feeds the purl namespace; ID + VersionID feed the
// distro= qualifier.
type osRelease struct {
	ID        string // e.g. "fedora", "rhel", "centos", "opensuse"
	VersionID string // e.g. "38", "9.2"
}

// Namespace returns the purl namespace (the vendor, lowercased) or "" when
// the os-release ID is unknown.
func (o osRelease) Namespace() string {
	return strings.ToLower(o.ID)
}

// Distro returns the value for the purl distro= qualifier (e.g. "fedora-38",
// "rhel-9.2") or "" when either component is missing.
func (o osRelease) Distro() string {
	if o.ID == "" || o.VersionID == "" {
		return ""
	}
	return strings.ToLower(o.ID) + "-" + o.VersionID
}

// readOSRelease reads the first os-release file found in source. A missing
// file is not an error — purls just get emitted without a namespace/distro.
func readOSRelease(source fs.FS) (osRelease, error) {
	for _, p := range osReleasePaths {
		f, err := source.Open(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return osRelease{}, err
		}
		o, err := parseOSRelease(f)
		//nolint:errcheck,gosec // close is best-effort on a read-only file
		f.Close()
		if err != nil {
			return osRelease{}, err
		}
		return o, nil
	}
	return osRelease{}, nil
}

// parseOSRelease parses the shell-fragment format used by os-release. Each
// line is KEY=VALUE; VALUE may be optionally double- or single-quoted. We
// only extract the keys we care about.
func parseOSRelease(r io.Reader) (osRelease, error) {
	var out osRelease
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
		return osRelease{}, err
	}
	return out, nil
}

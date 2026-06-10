// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"bufio"
	"io"
	"strings"
)

// dpkgPackage holds the fields we extract from one stanza of the dpkg status
// database (deb822 control format).
type dpkgPackage struct {
	Name          string
	Version       string // complete Debian version: [epoch:]upstream[-revision]
	Architecture  string
	Source        string // source package name, when it differs from Name
	SourceVersion string // source version when the Source field carries one
	Maintainer    string
	Email         string
	Homepage      string
	Summary       string // first line of the Description field
	Status        string // dpkg state triplet, e.g. "install ok installed"
}

// Installed reports whether the package is actually installed. The dpkg
// status file keeps stanzas for removed packages whose configuration is
// still around; those carry states like "deinstall ok config-files" and are
// not part of the system's software inventory. Distroless status.d stanzas
// have no Status field at all — their presence means installed.
func (p *dpkgPackage) Installed() bool {
	if p.Status == "" {
		return true
	}
	fields := strings.Fields(p.Status)
	return len(fields) == 3 && fields[2] == "installed"
}

// parseStatus parses a dpkg status database: a sequence of deb822 control
// stanzas separated by blank lines. It works both on the classic single
// status file (many stanzas) and on the per-package files distroless ships
// under status.d (one stanza each).
func parseStatus(r io.Reader) ([]*dpkgPackage, error) {
	var pkgs []*dpkgPackage
	var cur *dpkgPackage

	scanner := bufio.NewScanner(r)
	// Stanzas can run long (Conffiles lists); grow past the 64KiB default.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()

		// Blank line: stanza boundary.
		if strings.TrimSpace(line) == "" {
			if cur != nil {
				pkgs = append(pkgs, cur)
				cur = nil
			}
			continue
		}

		// Continuation lines (long Description bodies, Conffiles entries)
		// start with space or tab and belong to the previous field. We only
		// keep first lines, so skip them.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)

		if key == "Package" {
			if cur != nil {
				pkgs = append(pkgs, cur)
			}
			cur = &dpkgPackage{Name: value}
			continue
		}
		if cur == nil {
			continue
		}

		switch key {
		case "Version":
			cur.Version = value
		case "Architecture":
			cur.Architecture = value
		case "Source":
			cur.Source, cur.SourceVersion = splitSource(value)
		case "Maintainer":
			cur.Maintainer, cur.Email = splitMaintainer(value)
		case "Homepage":
			cur.Homepage = value
		case "Description":
			cur.Summary = value
		case "Status":
			cur.Status = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if cur != nil {
		pkgs = append(pkgs, cur)
	}
	return pkgs, nil
}

// splitSource splits a dpkg Source field into name and optional version.
// The field names the source package and may carry the source version in
// parentheses when it differs from the binary version:
//
//	Source: glibc
//	Source: glibc (2.31-13+deb11u6)
func splitSource(s string) (name, version string) {
	name, rest, found := strings.Cut(s, "(")
	name = strings.TrimSpace(name)
	if !found {
		return name, ""
	}
	return name, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ")"))
}

// splitMaintainer splits the RFC822-style "Name <email>" Maintainer field.
// When no angle brackets are present the whole value is returned as the name.
func splitMaintainer(s string) (name, email string) {
	name, rest, found := strings.Cut(s, "<")
	name = strings.TrimSpace(name)
	if !found {
		return name, ""
	}
	return name, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ">"))
}

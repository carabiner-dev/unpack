// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"bufio"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/carabiner-dev/unpack/license"
)

// packageLicenses reads the package's Debian copyright file and returns the
// distinct licenses found in it plus the package's umbrella license (the one
// declared for "Files: *"). Only machine-readable (DEP-5) copyright files
// are parsed; prose-format files and missing files yield no data — license
// enrichment is best-effort.
func packageLicenses(source fs.FS, pkgName string) (licenses []string, concluded string) {
	f, err := source.Open(path.Join("usr/share/doc", pkgName, "copyright"))
	if err != nil {
		return nil, ""
	}
	defer f.Close() //nolint:errcheck // read-only file

	return parseCopyright(f)
}

// parseCopyright extracts license data from a DEP-5 copyright file: a
// deb822 document whose header paragraph declares the machine-readable
// format and whose Files paragraphs each carry a License field. The first
// line of each License field is a short name or expression; continuation
// lines hold the license text and are ignored. Returns nothing when the
// file is not DEP-5.
func parseCopyright(r io.Reader) (licenses []string, concluded string) {
	var (
		isDEP5    bool
		seen      = map[string]bool{}
		filesGlob string // Files value of the current paragraph
		inHeader  = true
	)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			inHeader = false
			filesGlob = ""
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)

		switch key {
		case "Format":
			if inHeader && strings.Contains(value, "copyright-format/1.0") {
				isDEP5 = true
			}
		case "Files":
			filesGlob = value
		case "License":
			if value == "" {
				continue
			}
			norm := normalizeLicenseExpr(value)
			if !seen[norm] {
				seen[norm] = true
				licenses = append(licenses, norm)
			}
			// The license of the whole tree is the package's umbrella
			// license; a License field in the header paragraph is the
			// DEP-5 fallback for the same thing.
			if filesGlob == "*" || (inHeader && concluded == "") {
				concluded = norm
			}
		}
	}
	if err := scanner.Err(); err != nil || !isDEP5 {
		return nil, ""
	}
	slices.Sort(licenses)
	return licenses, concluded
}

// licenseOpRe matches the DEP-5 license expression operators so compound
// values like "BSD-2-clause or GPL-2" can be normalized component-wise.
var licenseOpRe = regexp.MustCompile(`\s+(and|or)\s+`)

// normalizeLicenseExpr converts a DEP-5 license expression to SPDX form:
// each component short name is mapped to its SPDX identifier and the
// lowercase DEP-5 operators become SPDX's uppercase ones.
func normalizeLicenseExpr(expr string) string {
	parts := licenseOpRe.Split(expr, -1)
	ops := licenseOpRe.FindAllStringSubmatch(expr, -1)

	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteByte(' ')
			b.WriteString(strings.ToUpper(ops[i-1][1]))
			b.WriteByte(' ')
		}
		b.WriteString(normalizeDEP5Name(part))
	}
	return b.String()
}

// dep5SPDXNames maps DEP-5 short names to SPDX identifiers where the two
// vocabularies disagree. The versioned GNU family is handled separately in
// normalizeDEP5Name; everything else missing here falls through to the
// generic license catalog.
var dep5SPDXNames = map[string]string{
	"Expat":    "MIT",
	"Zope":     "ZPL-2.1",
	"CC0":      "CC0-1.0",
	"Artistic": "Artistic-1.0-Perl",
}

// gnuFamilyRe matches the DEP-5 short names of the versioned GNU licenses
// (e.g. "GPL-2", "LGPL-2.1+", "GFDL-1.3"). The optional "+" means
// "or any later version".
var gnuFamilyRe = regexp.MustCompile(`^(A?GPL|LGPL|GFDL)-(\d+(?:\.\d+)?)(\+)?$`)

// normalizeDEP5Name maps one DEP-5 license short name to its SPDX
// identifier. Names with no SPDX equivalent (Debian-specific ones like
// "BSD-3-clause-Berkeley" or "public-domain") are returned as-is so
// downstream consumers can still see them.
func normalizeDEP5Name(name string) string {
	if spdx, ok := dep5SPDXNames[name]; ok {
		return spdx
	}

	// GPL-2 -> GPL-2.0-only, LGPL-2.1+ -> LGPL-2.1-or-later, ...
	if m := gnuFamilyRe.FindStringSubmatch(name); m != nil {
		version := m[2]
		if !strings.Contains(version, ".") {
			version += ".0"
		}
		suffix := "-only"
		if m[3] == "+" {
			suffix = "-or-later"
		}
		return m[1] + "-" + version + suffix
	}

	// The generic catalog fixes capitalization variants (e.g.
	// "BSD-2-clause" -> "BSD-2-Clause") and known aliases.
	return license.Normalize(name, "")
}

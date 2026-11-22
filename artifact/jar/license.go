// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package jar

import (
	"path"
	"slices"
	"strings"

	"github.com/carabiner-dev/unpack/license"
	"github.com/carabiner-dev/unpack/license/detect"
	"github.com/carabiner-dev/unpack/source/maven"
)

// This file reads how an archive says it is licensed. It may say so in
// three places, and they are tried in this order, the first that says
// anything settling it:
//
//   - the pom.xml Maven puts beside its pom.properties, when the project
//     declares its licenses there and does not inherit them;
//   - the manifest's Bundle-License, which OSGi bundles carry and many
//     plain jars too;
//   - the license file bundled in the archive, whose text is recognized.

// Sources of an archive's license.
const (
	LicenseFromPOM      = "pom.xml"
	LicenseFromManifest = "manifest"
	LicenseFromFile     = "license-file"
)

// maxLicenseFileSize is the size of the largest license file read.
const maxLicenseFileSize = 256 << 10

// isPOMXML says whether an entry is the POM Maven writes for an
// artifact: META-INF/maven/<group>/<artifact>/pom.xml.
func isPOMXML(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 5 && parts[0] == metaInf && parts[1] == "maven" && parts[4] == "pom.xml"
}

// pomKey is how a POM and a pom.properties of the same artifact find
// each other: by the directory Maven puts both in.
func pomKey(group, artifact string) string { return group + "/" + artifact }

// pomDeclares reads what an embedded POM declares itself: its licenses,
// and the organization behind it. What it inherits from a parent is not
// in the archive.
func pomDeclares(data []byte) (licenses []string, organization string) {
	pom, err := maven.ParsePomXMLData(data)
	if err != nil || pom == nil {
		return nil, ""
	}
	for _, declared := range pom.Licenses {
		if id := maven.NormalizeLicense(declared); id != "" && !slices.Contains(licenses, id) {
			licenses = append(licenses, id)
		}
	}
	if pom.Organization != nil {
		organization = strings.TrimSpace(pom.Organization.Name)
	}
	return licenses, organization
}

// bundleLicenses reads a Bundle-License header: clauses separated by
// commas, each an identifier or a URL, optionally followed by
// attributes after semicolons, of which link names the license's URL.
//
//	Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"
//	https://www.apache.org/licenses/LICENSE-2.0.txt
//
// A clause that is a URL no license is known by says nothing that can
// be passed on as a license, and is left out.
func bundleLicenses(header string) []string {
	licenses := []string{}
	for _, clause := range splitClauses(header) {
		parts := strings.Split(clause, ";")
		name := strings.Trim(strings.TrimSpace(parts[0]), `"`)
		link := ""
		for _, attribute := range parts[1:] {
			key, value, found := strings.Cut(strings.TrimSpace(attribute), "=")
			if found && strings.TrimSpace(key) == "link" {
				link = strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
		if name == "" {
			continue
		}
		var id string
		if isURL(name) {
			if id = license.Normalize("", name); id == "" || isURL(id) {
				continue
			}
		} else {
			id = license.Normalize(name, link)
		}
		if id != "" && !slices.Contains(licenses, id) {
			licenses = append(licenses, id)
		}
	}
	return licenses
}

func isURL(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

// splitClauses splits a header at the commas that are not inside
// quotes: a description attribute may hold one.
func splitClauses(header string) []string {
	clauses := []string{}
	start, quoted := 0, false
	for i, r := range header {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			clauses = append(clauses, header[start:i])
			start = i + 1
		}
	}
	return append(clauses, header[start:])
}

// isLicenseEntry says whether an entry is an archive's license file: one
// of the names license files go by, at the root of the archive or in its
// META-INF.
func isLicenseEntry(name string) bool {
	dir := path.Dir(name)
	return (dir == "." || dir == metaInf) && detect.IsFileName(path.Base(name))
}

// fileLicense recognizes the license a bundled license file holds.
func fileLicense(texts [][]byte) []string {
	for _, text := range texts {
		if id := detect.Text(text); id != "" {
			return []string{id}
		}
	}
	return nil
}

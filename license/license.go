// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package license provides SPDX license identifier normalization.
// It embeds the official SPDX license list and the CycloneDX curated
// alias mapping, then maps free-form license names and URLs to their
// canonical SPDX identifiers.
//
// Update the embedded data with:
//
//	go generate ./license/
package license

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:generate go run update.go

//go:embed licenses.json
var licensesJSON []byte

//go:embed mapping.json
var mappingJSON []byte

// spdxLicense is a single entry from the SPDX license list.
type spdxLicense struct {
	LicenseID string   `json:"licenseId"`
	Name      string   `json:"name"`
	SeeAlso   []string `json:"seeAlso"`
}

type spdxList struct {
	LicenseListVersion string        `json:"licenseListVersion"`
	Licenses           []spdxLicense `json:"licenses"`
}

// mappingEntry is a single entry from the CycloneDX license mapping.
type mappingEntry struct {
	Expression string   `json:"exp"`
	Names      []string `json:"names"`
}

// catalog holds the parsed license data and lookup maps.
type catalog struct {
	version  string
	byID     map[string]*spdxLicense // "Apache-2.0" -> license
	byName   map[string]*spdxLicense // lowercase name -> license
	byURL    map[string]*spdxLicense // normalized URL -> license
	byAlias  map[string]string       // lowercase alias name -> SPDX expression
}

var (
	defaultCatalog *catalog
	catalogOnce    sync.Once
)

func getCatalog() *catalog {
	catalogOnce.Do(func() {
		defaultCatalog = loadCatalog()
	})
	return defaultCatalog
}

func loadCatalog() *catalog {
	var list spdxList
	if err := json.Unmarshal(licensesJSON, &list); err != nil {
		panic("license: failed to parse embedded licenses.json: " + err.Error())
	}

	c := &catalog{
		version: list.LicenseListVersion,
		byID:    make(map[string]*spdxLicense, len(list.Licenses)),
		byName:  make(map[string]*spdxLicense, len(list.Licenses)),
		byURL:   make(map[string]*spdxLicense),
		byAlias: make(map[string]string),
	}

	for i := range list.Licenses {
		lic := &list.Licenses[i]
		c.byID[lic.LicenseID] = lic
		c.byName[strings.ToLower(lic.Name)] = lic

		for _, u := range lic.SeeAlso {
			norm := normalizeURL(u)
			if _, exists := c.byURL[norm]; !exists {
				c.byURL[norm] = lic
			} else {
				// Ambiguous: mark for removal
				c.byURL[norm] = nil
			}
		}
	}

	// Remove ambiguous URL mappings
	for k, v := range c.byURL {
		if v == nil {
			delete(c.byURL, k)
		}
	}

	// Load CycloneDX alias mapping
	var mapping []mappingEntry
	if err := json.Unmarshal(mappingJSON, &mapping); err != nil {
		panic("license: failed to parse embedded mapping.json: " + err.Error())
	}

	for _, entry := range mapping {
		for _, name := range entry.Names {
			c.byAlias[strings.ToLower(name)] = entry.Expression
		}
	}

	return c
}

// Version returns the embedded SPDX license list version.
func Version() string {
	return getCatalog().version
}

// Normalize maps a license name or URL to its SPDX identifier or expression.
// It tries the following in order:
//  1. Exact SPDX ID match (input is already a valid SPDX ID)
//  2. URL match against seeAlso cross-references from the SPDX license list
//  3. Name match against official SPDX license names (case-insensitive)
//  4. Name match against CycloneDX curated alias mapping (case-insensitive)
//
// Returns the original input unchanged if no match is found.
func Normalize(name, url string) string {
	c := getCatalog()

	// 1. Already a valid SPDX ID?
	if _, ok := c.byID[name]; ok {
		return name
	}

	// 2. URL match
	if url != "" {
		if lic, ok := c.byURL[normalizeURL(url)]; ok {
			return lic.LicenseID
		}
	}

	// 3. Official SPDX name match (case-insensitive)
	lower := strings.ToLower(name)
	if lic, ok := c.byName[lower]; ok {
		return lic.LicenseID
	}

	// 4. CycloneDX alias match (case-insensitive)
	if expr, ok := c.byAlias[lower]; ok {
		return expr
	}

	return name
}

// normalizeURL strips scheme, trailing slashes, file extensions, and
// lowercases for matching. Many POMs link to .txt or .html variants
// of the same license URL.
func normalizeURL(rawURL string) string {
	u := strings.ToLower(strings.TrimRight(rawURL, "/"))
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	for _, ext := range []string{".txt", ".html", ".htm", ".md"} {
		u = strings.TrimSuffix(u, ext)
	}
	return u
}

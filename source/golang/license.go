// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"archive/zip"
	"bytes"
	"strings"
	"sync"
	"time"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/mod/module"

	"github.com/carabiner-dev/unpack/license"

	khttp "sigs.k8s.io/release-utils/http"
)

const defaultLicenseTimeout = 30 * time.Second

// licenseFile names we look for inside module zips, in priority order.
var licenseFileNames = []string{
	"LICENSE",
	"LICENSE.md",
	"LICENSE.txt",
	"LICENCE",
	"LICENCE.md",
	"LICENCE.txt",
	"COPYING",
	"COPYING.md",
	"COPYING.txt",
}

var (
	defaultClassifier     *classifier.Classifier
	defaultClassifierOnce sync.Once
)

// getClassifier returns a shared license classifier instance,
// initialized lazily on first use.
func getClassifier() *classifier.Classifier {
	defaultClassifierOnce.Do(func() {
		c, err := assets.DefaultClassifier()
		if err == nil {
			defaultClassifier = c
		}
	})
	return defaultClassifier
}

// licenseClient fetches module zips from the Go proxy and extracts license files.
type licenseClient struct {
	agent    *khttp.Agent
	proxyURL string
}

// newLicenseClient creates a new license client for fetching module zips.
func newLicenseClient(proxyURL string, concurrency int) *licenseClient {
	if proxyURL == "" {
		proxyURL = defaultProxyURL
	}
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	agent := khttp.NewAgent().
		WithTimeout(defaultLicenseTimeout).
		WithMaxParallel(concurrency).
		WithFailOnHTTPError(true)

	return &licenseClient{
		agent:    agent,
		proxyURL: proxyURL,
	}
}

// moduleZipURL constructs the proxy URL for a module's zip archive.
func (lc *licenseClient) moduleZipURL(modPath, version string) string {
	escapedPath, err := module.EscapePath(modPath)
	if err != nil {
		return ""
	}
	return lc.proxyURL + "/" + escapedPath + "/@v/" + version + ".zip"
}

// modKey is a module path + version pair used as a map key.
type modKey struct {
	Path    string
	Version string
}

// FetchLicenses fetches module zips in parallel, extracts LICENSE files,
// and returns a map of "module@version" -> SPDX license identifier.
func (lc *licenseClient) FetchLicenses(modules []modKey) map[string]string {
	if len(modules) == 0 {
		return nil
	}

	// Build URL list, skipping modules with unescapable paths
	type fetchEntry struct {
		key string // "module@version"
		url string
	}
	var entries []fetchEntry
	for _, m := range modules {
		u := lc.moduleZipURL(m.Path, m.Version)
		if u == "" {
			continue
		}
		entries = append(entries, fetchEntry{
			key: m.Path + "@" + m.Version,
			url: u,
		})
	}

	if len(entries) == 0 {
		return nil
	}

	urls := make([]string, len(entries))
	for i, e := range entries {
		urls[i] = e.url
	}

	// Fetch all zips in parallel
	bodies, errs := lc.agent.GetGroup(urls)

	// Extract licenses from each zip
	result := make(map[string]string, len(entries))
	for i, e := range entries {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}

		lic := extractLicenseFromZip(bodies[i])
		if lic != "" {
			result[e.key] = lic
		}
	}

	return result
}

// extractLicenseFromZip opens a zip archive in memory and looks for a
// LICENSE file. If found, it classifies the content and returns a
// normalized SPDX identifier.
func extractLicenseFromZip(data []byte) string {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return ""
	}

	// Build a set of license file basenames for fast lookup
	licenseNames := make(map[string]struct{}, len(licenseFileNames))
	for _, name := range licenseFileNames {
		licenseNames[strings.ToUpper(name)] = struct{}{}
	}

	// Look for license files in the zip. Module zips have a prefix
	// like "github.com/foo/bar@v1.0.0/" so we find the module root
	// prefix first, then only consider license files directly under it.
	var modulePrefix string
	if len(r.File) > 0 {
		first := r.File[0].Name
		if idx := strings.Index(first, "@"); idx != -1 {
			if slashIdx := strings.Index(first[idx:], "/"); slashIdx != -1 {
				modulePrefix = first[:idx+slashIdx+1]
			}
		}
	}

	for _, f := range r.File {
		// Only consider files directly in the module root
		if modulePrefix != "" && !strings.HasPrefix(f.Name, modulePrefix) {
			continue
		}
		rel := strings.TrimPrefix(f.Name, modulePrefix)
		if strings.Contains(rel, "/") {
			continue // skip files in subdirectories
		}

		if _, ok := licenseNames[strings.ToUpper(rel)]; !ok {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		buf := make([]byte, min(f.UncompressedSize64, 64*1024)) // cap at 64KB
		n, _ := rc.Read(buf)
		rc.Close() //nolint:errcheck
		if n == 0 {
			continue
		}

		if lic := classifyLicenseText(buf[:n]); lic != "" {
			return lic
		}
	}

	return ""
}

// classifyLicenseText uses the Google license classifier to identify
// a license from its full text. Returns a normalized SPDX identifier
// or empty string if unrecognized.
func classifyLicenseText(content []byte) string {
	c := getClassifier()
	if c == nil {
		return ""
	}

	results := c.Match(content)

	// Find the highest-confidence match with MatchType "License",
	// skipping copyright notices and other non-license matches.
	for _, m := range results.Matches {
		if m.MatchType == "License" {
			return license.Normalize(m.Name, "")
		}
	}

	return ""
}

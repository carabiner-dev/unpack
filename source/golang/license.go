// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/mod/module"
	khttp "sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/unpack/license"
)

const (
	defaultLicenseTimeout = 30 * time.Second
	depsDevBaseURL        = "https://api.deps.dev/v3"
)

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

// depsDevVersionResponse is the JSON response from the deps.dev version API.
type depsDevVersionResponse struct {
	Licenses    []string      `json:"licenses"`
	PublishedAt string        `json:"publishedAt"`
	Links       []depsDevLink `json:"links"`
	Description string        `json:"description"`
}

// depsDevLink is a link entry in the deps.dev response.
type depsDevLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// licenseClient fetches license data from deps.dev, falling back to
// downloading module zips from the Go proxy when deps.dev doesn't
// have an entry.
type licenseClient struct {
	agent    *khttp.Agent
	proxyURL string
}

// newLicenseClient creates a new license client.
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

// modKey is a module path + version pair used as a map key.
type modKey struct {
	Path    string
	Version string
}

// licenseResult holds the enrichment data extracted from deps.dev or zip fallback.
type licenseResult struct {
	License   string
	SourceURL string // VCS repository URL
}

// FetchLicenses fetches license information for all modules. It first
// queries deps.dev in parallel, then falls back to downloading module
// zips from the Go proxy for any modules not found in deps.dev.
func (lc *licenseClient) FetchLicenses(modules []modKey) map[string]*licenseResult {
	if len(modules) == 0 {
		return nil
	}

	// Phase 1: query deps.dev for all modules in parallel
	result := lc.fetchFromDepsDev(modules)

	// Phase 2: collect modules that deps.dev didn't have
	var missing []modKey
	for _, m := range modules {
		key := m.Path + "@" + m.Version
		if _, ok := result[key]; !ok {
			missing = append(missing, m)
		}
	}

	// Phase 3: fall back to zip download for missing modules
	if len(missing) > 0 {
		zipResults := lc.fetchFromZips(missing)
		for k, v := range zipResults {
			result[k] = v
		}
	}

	return result
}

// fetchFromDepsDev queries the deps.dev API for license and link data.
func (lc *licenseClient) fetchFromDepsDev(modules []modKey) map[string]*licenseResult {
	// Build deps.dev URLs
	urls := make([]string, len(modules))
	for i, m := range modules {
		escapedName := strings.ReplaceAll(m.Path, "/", "%2F")
		urls[i] = fmt.Sprintf("%s/systems/go/packages/%s/versions/%s", depsDevBaseURL, escapedName, m.Version)
	}

	bodies, errs := lc.agent.GetGroup(urls)

	result := make(map[string]*licenseResult, len(modules))
	for i, m := range modules {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}

		var resp depsDevVersionResponse
		if err := json.Unmarshal(bodies[i], &resp); err != nil {
			continue
		}

		// Only use the result if we got license data
		if len(resp.Licenses) == 0 {
			continue
		}

		lr := &licenseResult{
			License: license.Normalize(resp.Licenses[0], ""),
		}

		// Extract source repo URL from links
		for _, link := range resp.Links {
			if link.Label == "SOURCE_REPO" && link.URL != "" {
				lr.SourceURL = link.URL
				break
			}
		}

		result[m.Path+"@"+m.Version] = lr
	}

	return result
}

// fetchFromZips downloads module zips from the Go proxy and extracts
// license files as a fallback when deps.dev doesn't have the data.
func (lc *licenseClient) fetchFromZips(modules []modKey) map[string]*licenseResult {
	// Build zip URLs
	type fetchEntry struct {
		key string
		url string
	}
	var entries []fetchEntry
	for _, m := range modules {
		escapedPath, err := module.EscapePath(m.Path)
		if err != nil {
			continue
		}
		u := lc.proxyURL + "/" + escapedPath + "/@v/" + m.Version + ".zip"
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

	bodies, errs := lc.agent.GetGroup(urls)

	result := make(map[string]*licenseResult, len(entries))
	for i, e := range entries {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}

		lic := extractLicenseFromZip(bodies[i])
		if lic != "" {
			result[e.key] = &licenseResult{License: lic}
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

	// Find the module root prefix from the first entry
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
		if modulePrefix != "" && !strings.HasPrefix(f.Name, modulePrefix) {
			continue
		}
		rel := strings.TrimPrefix(f.Name, modulePrefix)
		if strings.Contains(rel, "/") {
			continue
		}

		if _, ok := licenseNames[strings.ToUpper(rel)]; !ok {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		buf := make([]byte, min(f.UncompressedSize64, 64*1024))
		n, _ := rc.Read(buf) //nolint:errcheck
		rc.Close()           //nolint:errcheck,gosec
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
// a license from its full text.
func classifyLicenseText(content []byte) string {
	c := getClassifier()
	if c == nil {
		return ""
	}

	results := c.Match(content)

	for _, m := range results.Matches {
		if m.MatchType == "License" {
			return license.Normalize(m.Name, "")
		}
	}

	return ""
}

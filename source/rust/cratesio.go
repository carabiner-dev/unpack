// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"encoding/json"
	"fmt"
	"time"

	khttp "sigs.k8s.io/release-utils/http"
)

const (
	defaultCratesIOURL     = "https://crates.io/api/v1"
	defaultConcurrency     = 10
	defaultCratesIOTimeout = 30 * time.Second
)

// CratesIOClient fetches crate metadata from the crates.io API.
type CratesIOClient struct {
	Agent   *khttp.Agent
	BaseURL string
}

// crateVersionResponse is the top-level JSON response from /api/v1/crates/{name}/{version}.
type crateVersionResponse struct {
	Version crateVersion `json:"version"`
}

// crateVersion contains the fields we extract from the crates.io API.
type crateVersion struct {
	License       string `json:"license"`
	Description   string `json:"description"`
	Homepage      string `json:"homepage"`
	Documentation string `json:"documentation"`
	Repository    string `json:"repository"`
	Checksum      string `json:"checksum"`
	CrateSize     int    `json:"crate_size"`
	RustVersion   string `json:"rust_version"`
	Yanked        bool   `json:"yanked"`
}

// NewCratesIOClient creates a new client for the crates.io API.
func NewCratesIOClient(concurrency int) *CratesIOClient {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	agent := khttp.NewAgent().
		WithTimeout(defaultCratesIOTimeout).
		WithMaxParallel(concurrency).
		WithFailOnHTTPError(true)

	return &CratesIOClient{
		Agent:   agent,
		BaseURL: defaultCratesIOURL,
	}
}

// crateURL constructs the API URL for a specific crate version.
func (c *CratesIOClient) crateURL(name, version string) string {
	return fmt.Sprintf("%s/crates/%s/%s", c.BaseURL, name, version)
}

// FetchAll fetches metadata for multiple crates in parallel using the
// Agent's GetGroup. Returns a map of PackageKey to parsed metadata.
// Errors on individual crates are silently skipped.
func (c *CratesIOClient) FetchAll(packages []PackageKey) map[PackageKey]*crateVersion {
	if len(packages) == 0 {
		return nil
	}

	// Build URL list
	urls := make([]string, len(packages))
	for i, pkg := range packages {
		urls[i] = c.crateURL(pkg.Name, pkg.Version)
	}

	// Fetch all in parallel
	bodies, errs := c.Agent.GetGroup(urls)

	// Parse responses
	result := make(map[PackageKey]*crateVersion, len(packages))
	for i, pkg := range packages {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}

		var resp crateVersionResponse
		if err := json.Unmarshal(bodies[i], &resp); err != nil {
			continue
		}

		result[pkg] = &resp.Version
	}

	return result
}

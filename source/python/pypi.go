// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	khttp "sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/unpack/license"
)

// This file enriches the graph with what the package index knows and the
// lockfile does not. A uv.lock carries no licence data at all, so without
// this every Python SBOM is licence-empty; PyPI also knows a package's
// description, homepage and repository.

const (
	defaultPyPIURL     = "https://pypi.org/pypi"
	defaultConcurrency = 10
	defaultPyPITimeout = 30 * time.Second
)

// PyPIClient fetches package metadata from the PyPI JSON API.
type PyPIClient struct {
	Agent   *khttp.Agent
	BaseURL string
}

// NewPyPIClient creates a client for the PyPI JSON API.
func NewPyPIClient(concurrency int) *PyPIClient {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	return &PyPIClient{
		Agent: khttp.NewAgent().
			WithTimeout(defaultPyPITimeout).
			WithMaxParallel(concurrency).
			WithFailOnHTTPError(true),
		BaseURL: defaultPyPIURL,
	}
}

// pypiResponse is the top-level response of /pypi/{name}/{version}/json.
type pypiResponse struct {
	Info pypiInfo `json:"info"`
}

// pypiInfo holds the fields the enrichment reads.
type pypiInfo struct {
	// The three places PyPI states a licence, from best to worst: a
	// declared SPDX expression (PEP 639), a free-text field, and the trove
	// classifiers.
	LicenseExpression string   `json:"license_expression"`
	License           string   `json:"license"`
	Classifiers       []string `json:"classifiers"`

	Summary     string            `json:"summary"`
	HomePage    string            `json:"home_page"`
	ProjectURLs map[string]string `json:"project_urls"`
}

// FetchAll fetches metadata for the packages in parallel. Failures are
// skipped: enrichment adds what it can and never breaks an extraction.
func (c *PyPIClient) FetchAll(packages []packageKey) map[packageKey]*pypiInfo {
	if len(packages) == 0 {
		return nil
	}

	urls := make([]string, len(packages))
	for i, pkg := range packages {
		urls[i] = fmt.Sprintf("%s/%s/%s/json", c.BaseURL, pkg.name, pkg.version)
	}

	bodies, errs := c.Agent.GetGroup(urls)

	result := make(map[packageKey]*pypiInfo, len(packages))
	for i, pkg := range packages {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}
		var resp pypiResponse
		if err := json.Unmarshal(bodies[i], &resp); err != nil {
			continue
		}
		result[pkg] = &resp.Info
	}
	return result
}

// enrich fills the graph's nodes with what PyPI knows about them. The
// project's own packages are skipped: they are not on the index, and the
// lock is authoritative about them.
func (tb *treeBuilder) enrich(client *PyPIClient) {
	keys := make([]packageKey, 0, len(tb.nodes))
	for key := range tb.nodes {
		if !tb.rootKeys[key] {
			keys = append(keys, key)
		}
	}

	for key, info := range client.FetchAll(keys) {
		node, ok := tb.nodes[key]
		if !ok {
			continue
		}

		if licenses := pypiLicenses(info); len(licenses) > 0 {
			node.Licenses = licenses
		}
		if info.Summary != "" {
			node.Description = info.Summary
		}
		if home := pypiHomepage(info); home != "" {
			node.UrlHome = home
		}
		if repo := projectURL(info, "repository", "source", "source code", "github"); repo != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  repo,
				Type: sbom.ExternalReference_VCS,
			})
		}
		if docs := projectURL(info, "documentation", "docs"); docs != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  docs,
				Type: sbom.ExternalReference_DOCUMENTATION,
			})
		}
	}
}

// pypiLicenses reads the licence out of the three places PyPI may state
// one, best first.
//
// The declared expression (PEP 639) is already SPDX and wins outright. The
// free-text field is next: old packages stuff anything in it, including the
// whole licence text, so a value that does not look like a short name is
// ignored. Trove classifiers come last, and only the ones the licence
// catalog can name: a classifier such as "Apache Software License" does not
// say which version, and guessing would be inventing data.
func pypiLicenses(info *pypiInfo) []string {
	if info.LicenseExpression != "" {
		return []string{license.Normalize(info.LicenseExpression, "")}
	}

	if text := strings.TrimSpace(info.License); text != "" && text != "UNKNOWN" &&
		len(text) <= 100 && !strings.ContainsAny(text, "\n\r") {
		return []string{license.Normalize(text, "")}
	}

	licenses := []string{}
	for _, classifier := range info.Classifiers {
		name, found := strings.CutPrefix(classifier, "License :: ")
		if !found {
			continue
		}
		// The interesting part is the last segment: the OSI Approved
		// grouping in the middle names nothing.
		if i := strings.LastIndex(name, " :: "); i >= 0 {
			name = name[i+4:]
		}
		// Only a name the catalog recognizes becomes a licence. Normalize
		// returns its input unchanged when it has no answer, and a raw
		// trove name is not a licence identifier.
		if normalized := license.Normalize(name, ""); normalized != name {
			licenses = append(licenses, normalized)
		}
	}
	return licenses
}

// pypiHomepage returns the package's homepage: the dedicated field, or the
// project URL naming one.
func pypiHomepage(info *pypiInfo) string {
	if info.HomePage != "" {
		return info.HomePage
	}
	return projectURL(info, "homepage")
}

// projectURL finds the first project URL labeled with one of the names,
// compared case-insensitively: the labels are free-form and vary in case
// across packages.
func projectURL(info *pypiInfo, names ...string) string {
	for _, name := range names {
		for label, url := range info.ProjectURLs {
			if strings.EqualFold(label, name) && url != "" {
				return url
			}
		}
	}
	return ""
}

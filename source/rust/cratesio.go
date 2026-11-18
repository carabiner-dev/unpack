// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	khttp "sigs.k8s.io/release-utils/http"
)

const (
	defaultCratesIOURL     = "https://crates.io/api/v1"
	defaultConcurrency     = 10
	defaultCratesIOTimeout = 30 * time.Second

	// cratesIOUserAgent names this client to crates.io, whose policy is
	// to refuse requests that do not say who is asking: one sent with
	// Go's default User-Agent is answered 403.
	// See https://crates.io/data-access#api
	cratesIOUserAgent = "unpack (+https://github.com/carabiner-dev/unpack)"
)

// userAgentTransport sends every request with a fixed User-Agent.
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A RoundTripper must not modify the request it is given.
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}

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

	// PublishedBy is the crates.io account that published the version.
	// The registry leaves it out for versions published before it kept
	// track, and for those a pipeline published with no account behind
	// it.
	PublishedBy *cratePublisher `json:"published_by"`
}

// cratePublisher is a crates.io account, as a version names its publisher.
type cratePublisher struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	URL   string `json:"url"`
}

// supplier names the publisher as the supplier of what it published: the
// account's name, or its login when it states none, with its page. It is
// an account, which is a person's as far as the registry can tell, and
// nil when there is nothing to name.
func (p *cratePublisher) supplier() *sbom.Person {
	if p == nil {
		return nil
	}
	name := p.Name
	if name == "" {
		name = p.Login
	}
	if name == "" {
		return nil
	}
	return &sbom.Person{Name: name, Url: p.URL}
}

// NewCratesIOClient creates a new client for the crates.io API.
func NewCratesIOClient(concurrency int) *CratesIOClient {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	// The timeout is set before the client: the agent copies it onto the
	// client it is handed.
	agent := khttp.NewAgent().
		WithTimeout(defaultCratesIOTimeout).
		WithClient(&http.Client{
			Transport: &userAgentTransport{base: http.DefaultTransport, userAgent: cratesIOUserAgent},
		}).
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
	var failed int
	var firstErr error
	for i, pkg := range packages {
		if errs[i] != nil {
			failed++
			if firstErr == nil {
				firstErr = errs[i]
			}
			continue
		}
		if len(bodies[i]) == 0 {
			continue
		}

		var resp crateVersionResponse
		if err := json.Unmarshal(bodies[i], &resp); err != nil {
			continue
		}

		result[pkg] = &resp.Version
	}

	// A crate that fails is skipped, but not without a trace: every one
	// of them failing is how a refused client looks.
	if failed > 0 {
		slog.Debug("rust: crates.io requests failed, those crates get no metadata",
			"failed", failed, "requested", len(packages), "first_error", firstErr)
	}

	return result
}

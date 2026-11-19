// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/protobom/protobom/pkg/sbom"
	khttp "sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/unpack/internal/logging"
)

const (
	defaultCratesIOURL     = "https://crates.io/api/v1"
	defaultConcurrency     = 10
	defaultCratesIOTimeout = 30 * time.Second

	// defaultCratesIOInterval is how far apart requests to crates.io are
	// sent. The registry asks automated clients for no more than one
	// request a second and answers 429 to one going faster, after which
	// it tells it nothing at all for a while.
	// See https://crates.io/data-access#api
	defaultCratesIOInterval = time.Second

	// cratesIOGiveUpAfter is how many requests in a row may fail before
	// the rest are not sent: a registry that is refusing the client will
	// refuse the next one too, and each refusal is waited on.
	cratesIOGiveUpAfter = 3

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

	// RequestInterval is the least time between the start of one request
	// and the start of the next. It defaults to what crates.io asks of
	// automated clients; another registry speaking the same API may
	// allow less.
	RequestInterval time.Duration

	// Logger is where the client says what went wrong with its requests.
	// A decomposer sets it to its caller's; left nil, nothing is logged.
	Logger *clog.Logger
}

// logger returns the client's logger, and a silent one when it has none.
func (c *CratesIOClient) logger() *clog.Logger {
	if c.Logger == nil {
		return logging.Silent()
	}
	return c.Logger
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
//
// The concurrency is kept for the callers that state one. It bounds the
// agent's parallel requests, of which FetchAll makes none: crates.io is
// asked one crate at a time (see RequestInterval).
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
		Agent:           agent,
		BaseURL:         defaultCratesIOURL,
		RequestInterval: defaultCratesIOInterval,
	}
}

// crateURL constructs the API URL for a specific crate version.
func (c *CratesIOClient) crateURL(name, version string) string {
	return fmt.Sprintf("%s/crates/%s/%s", c.BaseURL, name, version)
}

// errCratesIOGaveUp marks the requests that were not sent because the ones
// before them kept failing.
var errCratesIOGaveUp = errors.New("not requested: the requests before it kept failing")

// FetchAll fetches metadata for multiple crates. Returns a map of
// PackageKey to parsed metadata. A crate whose request fails is skipped.
//
// The requests go one after the other, RequestInterval apart: the
// registry's limit is on how often it is asked, so sending several at once
// only gets them refused. A lockfile of some hundred crates therefore
// takes minutes to enrich. When several requests in a row fail the rest
// are not sent.
func (c *CratesIOClient) FetchAll(packages []PackageKey) map[PackageKey]*crateVersion {
	if len(packages) == 0 {
		return nil
	}

	bodies := make([][]byte, len(packages))
	errs := make([]error, len(packages))
	var last time.Time
	failedInARow := 0
	for i, pkg := range packages {
		if failedInARow >= cratesIOGiveUpAfter {
			errs[i] = errCratesIOGaveUp
			continue
		}
		if wait := c.RequestInterval - time.Since(last); i > 0 && wait > 0 {
			time.Sleep(wait)
		}
		last = time.Now()

		bodies[i], errs[i] = c.Agent.Get(c.crateURL(pkg.Name, pkg.Version))
		if errs[i] != nil {
			failedInARow++
		} else {
			failedInARow = 0
		}
	}

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
		c.logger().Debug("rust: crates.io requests failed, those crates get no metadata",
			"failed", failed, "requested", len(packages), "first_error", firstErr)
	}

	return result
}

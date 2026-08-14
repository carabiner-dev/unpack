// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	khttp "sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/unpack/license"
)

// This file enriches the graph with what the registry knows and the
// lockfile does not. A Gemfile.lock carries no licence data at all, so
// without this every Ruby SBOM is licence-empty; rubygems.org also knows a
// gem's description, homepage and repository, and — for locks written
// without checksums — the artifact's sha256.

const (
	defaultRubyGemsURL     = "https://rubygems.org/api/v2/rubygems"
	defaultConcurrency     = 10
	defaultRubyGemsTimeout = 30 * time.Second
)

// RubyGemsClient fetches gem metadata from the rubygems.org API.
type RubyGemsClient struct {
	Agent   *khttp.Agent
	BaseURL string
}

// NewRubyGemsClient creates a client for the rubygems.org API.
func NewRubyGemsClient(concurrency int) *RubyGemsClient {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	return &RubyGemsClient{
		Agent: khttp.NewAgent().
			WithTimeout(defaultRubyGemsTimeout).
			WithMaxParallel(concurrency).
			WithFailOnHTTPError(true),
		BaseURL: defaultRubyGemsURL,
	}
}

// gemVersionInfo holds the fields the enrichment reads from the
// version-exact endpoint.
type gemVersionInfo struct {
	// Licenses may be null in the registry: not every gem declares one.
	Licenses []string `json:"licenses"`

	Info          string `json:"info"`
	HomepageURI   string `json:"homepage_uri"`
	SourceCodeURI string `json:"source_code_uri"`

	// SHA is the sha256 of the pure-Ruby artifact.
	SHA string `json:"sha"`
}

// FetchAll fetches metadata for the gems in parallel. Failures are
// skipped: enrichment adds what it can and never breaks an extraction.
func (c *RubyGemsClient) FetchAll(specs []*GemSpec) map[*GemSpec]*gemVersionInfo {
	if len(specs) == 0 {
		return nil
	}

	urls := make([]string, len(specs))
	for i, spec := range specs {
		urls[i] = fmt.Sprintf("%s/%s/versions/%s.json", c.BaseURL, spec.Name, spec.Version)
	}

	bodies, errs := c.Agent.GetGroup(urls)

	result := make(map[*GemSpec]*gemVersionInfo, len(specs))
	for i, spec := range specs {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}
		info := &gemVersionInfo{}
		if err := json.Unmarshal(bodies[i], info); err != nil {
			continue
		}
		result[spec] = info
	}
	return result
}

// enrichNodes fills the graph's nodes with what the registry knows about
// them. Only registry gems are looked up: the index has nothing to say
// about the project's own node, nor about git and path gems, whose
// installed content is not the registry's artifact.
func (c *RubyGemsClient) enrichNodes(rb *rubyBuilder) {
	specs := []*GemSpec{}
	for name, spec := range rb.selected {
		if spec.Source.Type == "gem" && rb.nodes[name] != nil {
			specs = append(specs, spec)
		}
	}

	for spec, info := range c.FetchAll(specs) {
		node := rb.nodes[spec.Name]

		for _, id := range info.Licenses {
			if id != "" {
				node.Licenses = append(node.Licenses, license.Normalize(id, ""))
			}
		}
		if info.Info != "" {
			node.Description = info.Info
		}
		if info.HomepageURI != "" {
			node.UrlHome = info.HomepageURI
		}
		if info.SourceCodeURI != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  info.SourceCodeURI,
				Type: sbom.ExternalReference_VCS,
			})
		}

		// The endpoint's sha is the pure-Ruby artifact's: it fills the
		// gap a checksum-less lock leaves, for the node built from that
		// artifact, and never displaces a checksum the lock stated.
		if info.SHA != "" && spec.Platform == "" && len(node.GetHashes()) == 0 {
			node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): info.SHA}
		}
	}
}

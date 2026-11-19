// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	khttp "sigs.k8s.io/release-utils/http"
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

	// URLs lists the files of the version: its wheels and its sdist.
	URLs []pypiFile `json:"urls"`
}

// pypiFile is one distribution file of a version, as the index lists it.
type pypiFile struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Digests  struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

// artifactPicker picks, for the packages whose source stated no hash that
// names an artifact, the file the target environment would install out of
// the ones the index lists.
//
// A compiled requirements file is the case: it lists the hash of every
// file of a package, sdist and each wheel, without saying which is which,
// so none of them is the package's hash on its own. The index names each
// file with its hash, which ties one of the file's hashes to the artifact
// the environment installs.
type artifactPicker struct {
	env *Environment

	// allowed holds, for a package, the hashes its source accepts. A
	// package listed with none accepts any file the index has.
	allowed map[packageKey][]string
}

// pick returns the file the environment would install of those the source
// accepts: the best wheel by its filename tags, the sdist when no wheel
// fits, as an installer chooses. It returns nil when the index lists no
// file the source accepts, as for a file compiled against another index.
func (ap *artifactPicker) pick(key packageKey, files []pypiFile) *pypiFile {
	accepted := ap.allowed[key]

	best := (*pypiFile)(nil)
	bestScore := -1
	var sdist *pypiFile
	for i := range files {
		file := &files[i]
		if file.Digests.SHA256 == "" {
			continue
		}
		if len(accepted) > 0 && !slices.Contains(accepted, file.Digests.SHA256) {
			continue
		}
		if !strings.HasSuffix(file.Filename, ".whl") {
			if sdist == nil {
				sdist = file
			}
			continue
		}
		if score, ok := wheelScore(file.Filename, ap.env); ok && score > bestScore {
			best, bestScore = file, score
		}
	}
	if best != nil {
		return best
	}
	return sdist
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

	// Who the package says it is by, and who it says maintains it. Each
	// comes as a name and as a list of addresses, and packages fill in
	// either or both (see metadataPeople).
	Author          string `json:"author"`
	AuthorEmail     string `json:"author_email"`
	Maintainer      string `json:"maintainer"`
	MaintainerEmail string `json:"maintainer_email"`

	// files are the version's files, which the response lists beside
	// the info.
	files []pypiFile
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
		resp.Info.files = resp.URLs
		result[pkg] = &resp.Info
	}
	return result
}

// enrichNodes fills the graph's nodes with what PyPI knows about them.
// Only packages that came from the registry are looked up: the index has
// nothing to say about the project's own packages, nor about git, path and
// url dependencies, whose installed content is not the index's artifact.
// Every builder ends with this.
//
// artifacts is for the sources that state no hash naming an artifact: a
// node with no hash then takes the hash and location of the file the
// environment would install, as the index lists it. The lock builders
// pass nil: their locks name each artifact with its hash.
func (c *PyPIClient) enrichNodes(nodes map[packageKey]*sbom.Node, enrichable map[packageKey]bool, artifacts *artifactPicker) {
	keys := make([]packageKey, 0, len(nodes))
	for key := range nodes {
		if enrichable[key] {
			keys = append(keys, key)
		}
	}

	for key, info := range c.FetchAll(keys) {
		node, ok := nodes[key]
		if !ok {
			continue
		}

		if licenses := pypiLicenses(info); len(licenses) > 0 {
			node.Licenses = licenses
		}
		if artifacts != nil && len(node.GetHashes()) == 0 {
			if file := artifacts.pick(key, info.files); file != nil {
				node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): file.Digests.SHA256}
				if node.GetUrlDownload() == "" {
					node.UrlDownload = file.URL
				}
			}
		}
		if suppliers := pypiSuppliers(info); len(suppliers) > 0 {
			node.Suppliers = suppliers
		}
		if info.Summary != "" {
			node.Description = info.Summary
		}
		if home := pypiHomepage(info); home != "" {
			node.UrlHome = home
		}
		if repo := projectURL(info.ProjectURLs, "repository", "source", "source code", "github"); repo != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  repo,
				Type: sbom.ExternalReference_VCS,
			})
		}
		if docs := projectURL(info.ProjectURLs, "documentation", "docs"); docs != "" {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  docs,
				Type: sbom.ExternalReference_DOCUMENTATION,
			})
		}
	}
}

// pypiSuppliers names who a package is supplied by: its maintainers, the
// ones putting its releases out, and its authors when it names no
// maintainer, as most packages do not.
func pypiSuppliers(info *pypiInfo) []*sbom.Person {
	if maintainers := metadataPeople(info.Maintainer, info.MaintainerEmail); len(maintainers) > 0 {
		return maintainers
	}
	return metadataPeople(info.Author, info.AuthorEmail)
}

// metadataPeople reads the people a pair of core metadata fields names:
// Author and Author-email, or Maintainer and Maintainer-email.
//
// The address field is a list of mailboxes, and how a package uses the
// pair has changed. Older metadata puts one name in the first field and
// its bare address in the second. Metadata written from a pyproject.toml
// puts each person that has an address in the second, as "Name <address>",
// and only those without one in the first. So a mailbox carrying a name
// is a person of its own, and a bare address belongs to the name field.
// An address with no name anywhere names nobody.
func metadataPeople(name, addresses string) []*sbom.Person {
	name = strings.TrimSpace(name)

	people := []*sbom.Person{}
	bare := ""
	if list, err := mail.ParseAddressList(addresses); err == nil {
		for _, mailbox := range list {
			switch {
			case mailbox.Name != "":
				people = append(people, &sbom.Person{Name: mailbox.Name, Email: mailbox.Address})
			case bare == "":
				bare = mailbox.Address
			}
		}
	}

	if name != "" {
		people = append([]*sbom.Person{{Name: name, Email: bare}}, people...)
	}
	return people
}

// pypiLicenses reads the licence out of the three places PyPI may state
// one. The triage is shared with the dist-info reader: installed metadata
// states the same three tiers.
func pypiLicenses(info *pypiInfo) []string {
	return licensesFromMetadata(info.LicenseExpression, info.License, info.Classifiers)
}

// pypiHomepage returns the package's homepage: the dedicated field, or the
// project URL naming one.
func pypiHomepage(info *pypiInfo) string {
	if info.HomePage != "" {
		return info.HomePage
	}
	return projectURL(info.ProjectURLs, "homepage")
}

// projectURL finds the first project URL labeled with one of the names,
// compared case-insensitively: the labels are free-form and vary in case
// across packages. The PyPI API and installed metadata state the same map.
func projectURL(urls map[string]string, names ...string) string {
	for _, name := range names {
		for label, url := range urls {
			if strings.EqualFold(label, name) && url != "" {
				return url
			}
		}
	}
	return ""
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	khttp "sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/unpack/license"
)

// This file asks the npm registry what a lockfile does not say about the
// packages it locks: who each is supplied by and under what license. A
// lock records where a package was fetched from and its integrity, little
// or nothing else; the registry keeps, for every version, the manifest it
// was published with and the account that published it.

const (
	defaultRegistryURL         = "https://registry.npmjs.org"
	defaultRegistryConcurrency = 10
	defaultRegistryTimeout     = 30 * time.Second
)

// publicRegistryHosts are the hosts of the public npm registry: its own,
// and the mirror of it Yarn writes into its locks.
var publicRegistryHosts = map[string]struct{}{
	"registry.npmjs.org":   {},
	"registry.yarnpkg.com": {},
}

// RegistryClient fetches package metadata from the npm registry.
type RegistryClient struct {
	Agent   *khttp.Agent
	BaseURL string
}

// NewRegistryClient creates a client for the public npm registry.
func NewRegistryClient(concurrency int) *RegistryClient {
	if concurrency <= 0 {
		concurrency = defaultRegistryConcurrency
	}
	return &RegistryClient{
		Agent: khttp.NewAgent().
			WithTimeout(defaultRegistryTimeout).
			WithMaxParallel(concurrency).
			WithFailOnHTTPError(true),
		BaseURL: defaultRegistryURL,
	}
}

// registryVersion holds what the enrichment reads of one published
// version: /{name}/{version} answers with the version's manifest and what
// the registry adds to it.
type registryVersion struct {
	// Author is the author the package's manifest declares, if any.
	Author *registryPerson `json:"author"`

	// Publisher is the registry account that published the version. Its
	// name is the account's, not a person's.
	Publisher *registryPerson `json:"_npmUser"`

	// License is the license the manifest declares, and Licenses the
	// list older manifests declared several in.
	License  *registryLicense  `json:"license"`
	Licenses []registryLicense `json:"licenses"`

	// Dist is the tarball the registry serves for the version.
	Dist registryDist `json:"dist"`
}

// registryDist describes the tarball of a published version: where it is
// and what it hashes to. The integrity is in SRI form, sha512 for anything
// published in years; the shasum is the SHA-1 older versions have alone.
type registryDist struct {
	Tarball   string `json:"tarball"`
	Integrity string `json:"integrity"`
	Shasum    string `json:"shasum"`
}

// hashes returns the tarball's hash as a node takes it: the strongest of
// the integrity's, or the SHA-1 when there is no integrity to read.
func (d *registryDist) hashes() map[int32]string {
	if integrity := strongestIntegrity(d.Integrity); integrity != "" {
		if algorithm, hash, err := ParseIntegrity(integrity); err == nil && len(hash) > 0 {
			if hashAlgo := integrityAlgorithmToSBOM(algorithm); hashAlgo != sbom.HashAlgorithm_UNKNOWN {
				return map[int32]string{int32(hashAlgo): fmt.Sprintf("%x", hash)}
			}
		}
	}
	if shasum := strings.ToLower(strings.TrimSpace(d.Shasum)); sha1Hex.MatchString(shasum) {
		return map[int32]string{int32(sbom.HashAlgorithm_SHA1): shasum}
	}
	return nil
}

// sha1Hex matches a SHA-1 written in hexadecimal.
var sha1Hex = regexp.MustCompile(`^[0-9a-f]{40}$`)

// registryLicense is a license as npm manifests write one: an SPDX
// expression in a string, or, in older manifests, an object naming its
// type and where it is found.
type registryLicense struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// UnmarshalJSON reads a license in either form. A value that is neither
// states no license rather than failing the document it is in.
func (l *registryLicense) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		l.Type = text
		return nil
	}

	type object registryLicense
	var o object
	if err := json.Unmarshal(data, &o); err == nil {
		*l = registryLicense(o)
	}
	return nil
}

// licenses returns the licenses the version declares, normalized: the
// license field, or the older list when there is none.
//
// Two values npm gives a meaning of its own are not licenses and state
// none. "UNLICENSED" says the package grants no license at all, which is
// not an identifier to pass on as if it were one, and "SEE LICENSE IN
// <file>" points at a file of the package this reader does not open.
func (v *registryVersion) licenses() []string {
	declared := v.Licenses
	if v.License != nil {
		declared = []registryLicense{*v.License}
	}

	licenses := []string{}
	for _, l := range declared {
		name := strings.TrimSpace(l.Type)
		upper := strings.ToUpper(name)
		if name == "" || upper == "UNLICENSED" || strings.HasPrefix(upper, "SEE LICENSE IN") {
			continue
		}
		if id := license.Normalize(name, l.URL); !slices.Contains(licenses, id) {
			licenses = append(licenses, id)
		}
	}
	return licenses
}

// registryPerson is a person as npm manifests write one: an object, or
// one string, "Name <email> (url)", of which only the name is required.
type registryPerson struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

// personString takes apart the one-string form of a person.
var personString = regexp.MustCompile(`^\s*([^<(]*?)\s*(?:<([^>]*)>)?\s*(?:\(([^)]*)\))?\s*$`)

// UnmarshalJSON reads a person in either form. A value that is neither
// names nobody rather than failing the document it is in.
func (p *registryPerson) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		if m := personString.FindStringSubmatch(text); m != nil {
			p.Name, p.Email, p.URL = m[1], strings.TrimSpace(m[2]), strings.TrimSpace(m[3])
		}
		return nil
	}

	type object registryPerson
	var o object
	if err := json.Unmarshal(data, &o); err == nil {
		*p = registryPerson(o)
	}
	return nil
}

// person names the entry as a supplier, or nil when it has no name.
func (p *registryPerson) person() *sbom.Person {
	if p == nil || strings.TrimSpace(p.Name) == "" {
		return nil
	}
	return &sbom.Person{
		Name:  strings.TrimSpace(p.Name),
		Email: strings.TrimSpace(p.Email),
		Url:   strings.TrimSpace(p.URL),
	}
}

// supplier names who the version is supplied by: the author its manifest
// declares, and for the many packages declaring none, the account that
// published it. Whether either is a person or an organization the
// registry does not say.
func (v *registryVersion) supplier() *sbom.Person {
	if author := v.Author.person(); author != nil {
		return author
	}
	return v.Publisher.person()
}

// versionURL is where the registry answers for one version of a package.
// A scoped name holds a slash, which the registry wants escaped.
func (c *RegistryClient) versionURL(name, version string) string {
	return fmt.Sprintf("%s/%s/%s", c.BaseURL, url.PathEscape(name), url.PathEscape(version))
}

// FetchAll fetches the metadata of the packages in parallel. Failures are
// skipped: enrichment adds what it can and never breaks an extraction.
func (c *RegistryClient) FetchAll(packages []PackageKey) map[PackageKey]*registryVersion {
	if len(packages) == 0 {
		return nil
	}

	urls := make([]string, len(packages))
	for i, pkg := range packages {
		urls[i] = c.versionURL(pkg.Name, pkg.Version)
	}
	bodies, errs := c.Agent.GetGroup(urls)

	result := make(map[PackageKey]*registryVersion, len(packages))
	for i, pkg := range packages {
		if errs[i] != nil || len(bodies[i]) == 0 {
			continue
		}
		version := &registryVersion{}
		if err := json.Unmarshal(bodies[i], version); err != nil {
			continue
		}
		result[pkg] = version
	}
	return result
}

// fromPublicRegistry says whether a node's package was fetched from the
// public registry, by where its lock says it was downloaded from.
//
// Only those are looked up. A package from a private registry, a git
// repository or a directory is not the public registry's to describe, and
// asking for it would tell the public registry the name of something that
// may be nobody else's business. A lock that does not say where a package
// came from gets nothing looked up.
func fromPublicRegistry(node *sbom.Node) bool {
	return isPublicRegistryURL(node.GetUrlDownload())
}

// plainVersion says whether a version is one a registry would have: a
// reference to a file, a link or a repository holds a colon or a slash.
func plainVersion(version string) bool {
	return version != "" && !strings.ContainsAny(version, ":/")
}

// enrichNodes fills the graph's nodes with what the registry knows about
// them: for each package that is the public registry's to describe, its
// supplier, and what its lock did not state of its license, its tarball
// and the tarball's hash. public says which those are, as each kind of
// lock can tell. The roots are the project's own packages and never asked
// about.
//
// What a lock recorded always stands. It is what was installed, and for
// the hash it is the stronger statement: a lock pins the content, where
// the registry only says what it serves for the version today.
func (c *RegistryClient) enrichNodes(nl *sbom.NodeList, public func(*sbom.Node) bool) {
	roots := map[string]struct{}{}
	for _, id := range nl.GetRootElements() {
		roots[id] = struct{}{}
	}

	byKey := map[PackageKey][]*sbom.Node{}
	keys := []PackageKey{}
	for _, node := range nl.GetNodes() {
		if _, isRoot := roots[node.GetId()]; isRoot {
			continue
		}
		if node.GetName() == "" || !plainVersion(node.GetVersion()) || !public(node) {
			continue
		}
		key := PackageKey{Name: node.GetName(), Version: node.GetVersion()}
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], node)
	}

	for key, version := range c.FetchAll(keys) {
		supplier, licenses := version.supplier(), version.licenses()
		// A package installed at several paths is several nodes.
		for _, node := range byKey[key] {
			if supplier != nil {
				node.Suppliers = []*sbom.Person{supplier.Copy()}
			}
			if len(licenses) > 0 && len(node.GetLicenses()) == 0 {
				node.Licenses = slices.Clone(licenses)
			}
			if len(node.GetHashes()) == 0 {
				if hashes := version.Dist.hashes(); hashes != nil {
					node.Hashes = hashes
				}
			}
			if node.GetUrlDownload() == "" && isPublicRegistryURL(version.Dist.Tarball) {
				node.UrlDownload = version.Dist.Tarball
			}
		}
	}
}

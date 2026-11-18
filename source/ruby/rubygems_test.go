// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// TestEnrich runs an extraction against a fake registry and checks the
// metadata lands on the right nodes and only on them.
// TestGemAuthors checks how the registry's authors string is read: names
// parted by commas, except where the comma belongs to a company's name.
func TestGemAuthors(t *testing.T) {
	t.Parallel()

	for authors, expected := range map[string][]string{
		"Leah Neukirchen":                          {"Leah Neukirchen"},
		"Blake Mizerany, Ryan Tomayko,Simon Rozet": {"Blake Mizerany", "Ryan Tomayko", "Simon Rozet"},
		"Example, Inc.":                            {"Example, Inc."},
		"Jane Doe, Example, Inc, Other":            {"Jane Doe", "Example, Inc", "Other"},
		"Example GmbH, Acme, LLC":                  {"Example GmbH", "Acme, LLC"},
		// Nothing before it to belong to.
		"Inc., Jane Doe": {"Inc.", "Jane Doe"},
		// rack-protection states a link in place of names.
		"https://github.com/sinatra/sinatra/graphs/contributors": {},
		"Jane Doe, https://example.com/contributors":             {"Jane Doe"},
		" , ,": {},
		"":     {},
	} {
		people := gemAuthors(authors)
		names := make([]string, 0, len(people))
		for _, person := range people {
			names = append(names, person.GetName())
			require.False(t, person.GetIsOrg())
		}
		require.Equal(t, expected, names, "authors %q", authors)
	}
}

func TestEnrich(t *testing.T) {
	t.Parallel()

	// The client fetches in parallel, so the handler runs concurrently:
	// everything it touches must be guarded.
	var mu sync.Mutex
	requested := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path] = true
		mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/sinatra/versions/"):
			//nolint:errcheck // a fake server's writes have nowhere to fail
			fmt.Fprint(w, `{"licenses": ["MIT"], "authors": "Blake Mizerany, Ryan Tomayko, Simon Rozet, Konstantin Haase", "info": "Classy web-development dressed in a DSL.", "homepage_uri": "http://sinatrarb.com/", "source_code_uri": "https://github.com/sinatra/sinatra", "sha": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`)
		case strings.HasPrefix(r.URL.Path, "/ffi/versions/"):
			//nolint:errcheck // a fake server's writes have nowhere to fail
			fmt.Fprint(w, `{"licenses": null, "info": "Foreign function interface.", "sha": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	lock, err := ReadGemLockfile("testdata/simple")
	require.NoError(t, err)
	rb, err := newRubyBuilder(lock, "testdata/simple", &api.DecomposerOptions{}, "linux/amd64")
	require.NoError(t, err)
	nl, err := rb.build()
	require.NoError(t, err)

	client := NewRubyGemsClient(2)
	client.BaseURL = server.URL
	client.enrichNodes(rb)

	sinatra := nodeNamed(t, nl, "sinatra")
	require.Equal(t, []string{"MIT"}, sinatra.GetLicenses())
	require.Equal(t, "Classy web-development dressed in a DSL.", sinatra.GetDescription())

	// The suppliers are the authors the registry names, in its order.
	names := make([]string, 0, len(sinatra.GetSuppliers()))
	for _, supplier := range sinatra.GetSuppliers() {
		names = append(names, supplier.GetName())
	}
	require.Equal(t, []string{"Blake Mizerany", "Ryan Tomayko", "Simon Rozet", "Konstantin Haase"}, names)
	require.Equal(t, "http://sinatrarb.com/", sinatra.GetUrlHome())
	require.Len(t, sinatra.GetExternalReferences(), 1)
	require.Equal(t, sbom.ExternalReference_VCS, sinatra.GetExternalReferences()[0].GetType())

	// The lock stated checksums, and the registry's sha must not
	// displace them: sinatra keeps the lock's, not the fake's.
	require.NotEqual(t, strings.Repeat("f", 64),
		sinatra.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	// Null licences enrich nothing, and the selected ffi is a platform
	// variant, so the pure-Ruby sha does not apply to it either.
	ffi := nodeNamed(t, nl, "ffi")
	require.Empty(t, ffi.GetLicenses())
	require.Empty(t, ffi.GetSuppliers(), "the registry named nobody")
	require.NotEqual(t, strings.Repeat("e", 64),
		ffi.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	// A gem the registry does not know keeps what the lock said.
	rack := nodeNamed(t, nl, "rack")
	require.Empty(t, rack.GetLicenses())
	require.NotEmpty(t, rack.GetHashes(), "enrichment must not touch the lock's data")
}

// TestEnrichFillsMissingHashes covers a lock written without checksums:
// the registry's sha fills the gap, for the pure-Ruby artifact it hashes.
func TestEnrichFillsMissingHashes(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck // a fake server's writes have nowhere to fail
		fmt.Fprint(w, `{"licenses": ["Apache-2.0"], "sha": "abababababababababababababababababababababababababababababababab"}`)
	}))
	defer server.Close()

	lock, err := ParseGemLockfile([]byte(`GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)

PLATFORMS
  ruby

DEPENDENCIES
  rake

BUNDLED WITH
   2.5.0
`))
	require.NoError(t, err)

	rb, err := newRubyBuilder(lock, ".", &api.DecomposerOptions{}, "linux/amd64")
	require.NoError(t, err)
	nl, err := rb.build()
	require.NoError(t, err)

	client := NewRubyGemsClient(1)
	client.BaseURL = server.URL
	client.enrichNodes(rb)

	rake := nodeNamed(t, nl, "rake")
	require.Equal(t, strings.Repeat("ab", 32), rake.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	require.Equal(t, []string{"Apache-2.0"}, rake.GetLicenses())
}

// TestEnrichSkipsNonRegistry pins which gems the registry may be asked
// about: a git gem's content is not the registry's artifact, even when a
// gem of the same name exists there.
func TestEnrichSkipsNonRegistry(t *testing.T) {
	t.Parallel()

	var requested atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	lock, err := ReadGemLockfile("testdata/gitgem")
	require.NoError(t, err)
	rb, err := newRubyBuilder(lock, "testdata/gitgem", &api.DecomposerOptions{}, "linux/amd64")
	require.NoError(t, err)
	_, err = rb.build()
	require.NoError(t, err)

	client := NewRubyGemsClient(1)
	client.BaseURL = server.URL
	client.enrichNodes(rb)
	require.Zero(t, requested.Load(), "nothing in this lock came from the registry")
}

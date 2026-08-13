// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// TestPyPILicenses covers the three places PyPI states a licence and the
// guards between them. The field shapes are the ones real packages have:
// click and numpy declare expressions, requests uses the free-text field,
// and old packages stuff whole licence texts into it.
func TestPyPILicenses(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		info     pypiInfo
		expected []string
	}{
		"a declared expression wins": {
			pypiInfo{LicenseExpression: "BSD-3-Clause", License: "something else"},
			[]string{"BSD-3-Clause"},
		},
		"a compound declared expression": {
			pypiInfo{LicenseExpression: "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0"},
			[]string{"BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0"},
		},
		"the free-text field": {
			pypiInfo{License: "Apache-2.0"},
			[]string{"Apache-2.0"},
		},
		"free text is normalized": {
			pypiInfo{License: "Apache License, Version 2.0"},
			[]string{"Apache-2.0"},
		},
		"a whole licence text is not a licence name": {
			pypiInfo{License: "Copyright (c) 2010 Somebody\n\nPermission is hereby granted, free of charge..."},
			[]string{},
		},
		"UNKNOWN is not a licence": {
			pypiInfo{License: "UNKNOWN"},
			[]string{},
		},
		"a classifier the catalog recognizes": {
			pypiInfo{Classifiers: []string{
				"Development Status :: 5 - Production/Stable",
				"License :: OSI Approved :: MIT License",
			}},
			[]string{"MIT"},
		},
		"a classifier the catalog cannot name": {
			// Which Apache? The classifier does not say, and guessing
			// would be inventing data.
			pypiInfo{Classifiers: []string{"License :: OSI Approved :: Apache Software License"}},
			[]string{},
		},
		"nothing at all": {
			pypiInfo{},
			[]string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, pypiLicenses(&tc.info))
		})
	}
}

func TestPyPIProjectURLs(t *testing.T) {
	t.Parallel()

	// The labels are free-form and vary in case across packages.
	info := &pypiInfo{ProjectURLs: map[string]string{
		"Source Code":   "https://github.com/example/project",
		"documentation": "https://example.readthedocs.io",
		"Changelog":     "https://example.com/changes",
	}}
	require.Equal(t, "https://github.com/example/project",
		projectURL(info.ProjectURLs, "repository", "source", "source code"))
	require.Equal(t, "https://example.readthedocs.io",
		projectURL(info.ProjectURLs, "documentation", "docs"))
	require.Empty(t, projectURL(info.ProjectURLs, "homepage"))
}

// TestEnrich runs an extraction against a fake PyPI and checks the metadata
// lands on the right nodes and only on them.
func TestEnrich(t *testing.T) {
	t.Parallel()

	requested := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested[r.URL.Path] = true
		switch {
		case strings.HasPrefix(r.URL.Path, "/requests/"):
			fmt.Fprint(w, `{"info": {"license": "Apache-2.0", "summary": "Python HTTP for Humans.", "project_urls": {"Homepage": "https://requests.readthedocs.io", "Source": "https://github.com/psf/requests"}}}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		case strings.HasPrefix(r.URL.Path, "/click/"):
			fmt.Fprint(w, `{"info": {"license_expression": "BSD-3-Clause", "summary": "Composable command line interface toolkit"}}`) //nolint:errcheck // a fake server's writes have nowhere to fail
		default:
			// Everything else gets no metadata: enrichment must cope.
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	lock, err := ReadLockfile("testdata/simple/uv.lock")
	require.NoError(t, err)
	env, err := NewEnvironment("linux", "amd64", "3.12")
	require.NoError(t, err)

	tb := newTreeBuilder(lock, env, &api.DecomposerOptions{})
	nl, err := tb.build()
	require.NoError(t, err)

	client := NewPyPIClient(2)
	client.BaseURL = server.URL
	client.enrichNodes(tb.nodes, tb.enrichable)

	requests := nodeNamed(t, nl, "requests")
	require.Equal(t, []string{"Apache-2.0"}, requests.GetLicenses())
	require.Equal(t, "Python HTTP for Humans.", requests.GetDescription())
	require.Equal(t, "https://requests.readthedocs.io", requests.GetUrlHome())
	require.Len(t, requests.GetExternalReferences(), 1)
	require.Equal(t, sbom.ExternalReference_VCS, requests.GetExternalReferences()[0].GetType())
	require.Equal(t, "https://github.com/psf/requests", requests.GetExternalReferences()[0].GetUrl())

	click := nodeNamed(t, nl, "click")
	require.Equal(t, []string{"BSD-3-Clause"}, click.GetLicenses())

	// A package the index knows nothing about keeps what the lock said.
	idna := nodeNamed(t, nl, "idna")
	require.Empty(t, idna.GetLicenses())
	require.NotEmpty(t, idna.GetHashes(), "enrichment must not touch the lock's data")

	// The project's own package was not looked up: it is not on PyPI.
	for path := range requested {
		require.NotContains(t, path, "/uvdemo/")
	}
	root := nodeNamed(t, nl, "uvdemo")
	require.Empty(t, root.GetLicenses())
}

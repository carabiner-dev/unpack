// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
// TestPyPISuppliers checks who a package's metadata names as its supplier,
// over the ways packages on the index fill those fields in. The cases are
// what PyPI states for the packages named.
func TestPyPISuppliers(t *testing.T) {
	t.Parallel()

	type person struct{ name, email string }
	for name, tc := range map[string]struct {
		info     pypiInfo
		expected []person
	}{
		// requests: one name and its bare address.
		"a name and a bare address": {
			pypiInfo{Author: "Kenneth Reitz", AuthorEmail: "me@kennethreitz.org"},
			[]person{{"Kenneth Reitz", "me@kennethreitz.org"}},
		},
		// idna: the name is in the address field alone.
		"a named address": {
			pypiInfo{AuthorEmail: "Kim Davies <kim+pypi@gumleaf.org>"},
			[]person{{"Kim Davies", "kim+pypi@gumleaf.org"}},
		},
		// click: no author, a maintainer.
		"only a maintainer": {
			pypiInfo{Maintainer: "Pallets", MaintainerEmail: "contact@palletsprojects.com"},
			[]person{{"Pallets", "contact@palletsprojects.com"}},
		},
		// urllib3: an author and several maintainers, who supply it.
		"maintainers over the author": {
			pypiInfo{
				AuthorEmail:     "Andrey Petrov <andrey.petrov@shazow.net>",
				MaintainerEmail: "Seth Michael Larson <sethmichaellarson@gmail.com>, Quentin Pradet <quentin@pradet.me>, Illia Volochii <illia.volochii@gmail.com>",
			},
			[]person{
				{"Seth Michael Larson", "sethmichaellarson@gmail.com"},
				{"Quentin Pradet", "quentin@pradet.me"},
				{"Illia Volochii", "illia.volochii@gmail.com"},
			},
		},
		// numpy: an author with no address, a maintainer with one.
		"a maintainer named in its address": {
			pypiInfo{Author: "Travis E. Oliphant et al.", MaintainerEmail: "NumPy Developers <numpy-discussion@python.org>"},
			[]person{{"NumPy Developers", "numpy-discussion@python.org"}},
		},
		"a name without an address, beside named ones": {
			pypiInfo{Author: "The Project", AuthorEmail: "Jane Doe <jane@example.com>"},
			[]person{{"The Project", ""}, {"Jane Doe", "jane@example.com"}},
		},
		"an address nobody is named for": {
			pypiInfo{AuthorEmail: "someone@example.com"},
			nil,
		},
		"an address field that is not one": {
			pypiInfo{Author: "Jane Doe", AuthorEmail: "not an address"},
			[]person{{"Jane Doe", ""}},
		},
		"nothing": {pypiInfo{}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var got []person
			for _, p := range pypiSuppliers(&tc.info) {
				got = append(got, person{p.GetName(), p.GetEmail()})
			}
			require.Equal(t, tc.expected, got)
		})
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
		case strings.HasPrefix(r.URL.Path, "/requests/"):
			fmt.Fprint(w, `{"info": {"license": "Apache-2.0", "summary": "Python HTTP for Humans.", "author": "Kenneth Reitz", "author_email": "me@kennethreitz.org", "maintainer": null, "maintainer_email": null, "project_urls": {"Homepage": "https://requests.readthedocs.io", "Source": "https://github.com/psf/requests"}}}`) //nolint:errcheck // a fake server's writes have nowhere to fail
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
	client.enrichNodes(tb.nodes, tb.enrichable, nil)

	requests := nodeNamed(t, nl, "requests")
	require.Equal(t, []string{"Apache-2.0"}, requests.GetLicenses())
	require.Equal(t, "Python HTTP for Humans.", requests.GetDescription())
	require.Equal(t, "https://requests.readthedocs.io", requests.GetUrlHome())
	require.Len(t, requests.GetExternalReferences(), 1)
	require.Equal(t, sbom.ExternalReference_VCS, requests.GetExternalReferences()[0].GetType())
	require.Equal(t, "https://github.com/psf/requests", requests.GetExternalReferences()[0].GetUrl())

	// The supplier is who the index says the package is by.
	require.Len(t, requests.GetSuppliers(), 1)
	require.Equal(t, "Kenneth Reitz", requests.GetSuppliers()[0].GetName())
	require.Equal(t, "me@kennethreitz.org", requests.GetSuppliers()[0].GetEmail())

	click := nodeNamed(t, nl, "click")
	require.Equal(t, []string{"BSD-3-Clause"}, click.GetLicenses())
	require.Empty(t, click.GetSuppliers(), "the index named nobody")

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

// TestArtifactPicker checks which of the files the index lists is taken
// for a package whose source did not say: the one the target environment
// installs, out of those the source accepts.
func TestArtifactPicker(t *testing.T) {
	t.Parallel()

	file := func(name, sha string) pypiFile {
		f := pypiFile{Filename: name, URL: "https://files.pythonhosted.org/packages/" + name}
		f.Digests.SHA256 = sha
		return f
	}
	files := []pypiFile{
		file("pkg-1.0.tar.gz", "sdist"),
		file("pkg-1.0-py3-none-any.whl", "universal"),
		file("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "linux312"),
		file("pkg-1.0-cp312-cp312-win_amd64.whl", "win312"),
		file("pkg-1.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "linux311"),
	}
	key := packageKey{name: "pkg", version: "1.0"}

	linux, err := NewEnvironment("linux", "amd64", "3.12")
	require.NoError(t, err)
	windows, err := NewEnvironment("windows", "amd64", "3.12")
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		env      *Environment
		allowed  []string
		files    []pypiFile
		expected string
	}{
		// A compiled file accepts every file of the package: the
		// environment decides.
		"the wheel built for the environment": {
			linux, []string{"sdist", "universal", "linux312", "win312", "linux311"}, files, "linux312",
		},
		"the same file list, another platform": {
			windows, []string{"sdist", "universal", "linux312", "win312", "linux311"}, files, "win312",
		},
		// What the source does not accept is not installed, whatever
		// fits best.
		"only what the source accepts":          {linux, []string{"sdist", "universal"}, files, "universal"},
		"the sdist when no accepted wheel fits": {linux, []string{"sdist", "win312"}, files, "sdist"},
		// A source stating no hash accepts whatever the index has.
		"no hashes stated": {linux, nil, files, "linux312"},
		// A file compiled against another index, or since changed.
		"nothing the source accepts": {linux, []string{"somewhere-else"}, files, ""},
		"an index listing no files":  {linux, nil, nil, ""},
		"a file with no digest":      {linux, nil, []pypiFile{{Filename: "pkg-1.0-py3-none-any.whl"}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			picker := &artifactPicker{env: tc.env, allowed: map[packageKey][]string{key: tc.allowed}}
			picked := picker.pick(key, tc.files)
			if tc.expected == "" {
				require.Nil(t, picked)
				return
			}
			require.NotNil(t, picked)
			require.Equal(t, tc.expected, picked.Digests.SHA256)
		})
	}
}

// TestEnrichPicksArtifacts checks the hash and location of the picked file
// reach a node that had no hash, that a node with one keeps it, and that
// the lock builders, which pass no picker, are left alone.
func TestEnrichPicksArtifacts(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		//nolint:errcheck // a fake server's writes have nowhere to fail
		fmt.Fprint(w, `{"info": {}, "urls": [
			{"filename": "pkg-1.0.tar.gz", "url": "https://files.example/pkg-1.0.tar.gz", "digests": {"sha256": "sdist"}},
			{"filename": "pkg-1.0-py3-none-any.whl", "url": "https://files.example/pkg-1.0-py3-none-any.whl", "digests": {"sha256": "wheel"}}
		]}`)
	}))
	defer server.Close()

	env, err := NewEnvironment("linux", "amd64", "3.12")
	require.NoError(t, err)

	newNodes := func() (nodes map[packageKey]*sbom.Node, enrichable map[packageKey]bool) {
		nodes = map[packageKey]*sbom.Node{
			{name: "compiled", version: "1.0"}: {Name: "compiled", Version: "1.0"},
			{name: "single", version: "1.0"}: {
				Name: "single", Version: "1.0", UrlDownload: "https://as.stated/single.whl",
				Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): "stated"},
			},
			{name: "foreign", version: "1.0"}: {Name: "foreign", Version: "1.0"},
		}
		enrichable = map[packageKey]bool{}
		for key := range nodes {
			enrichable[key] = true
		}
		return nodes, enrichable
	}

	client := NewPyPIClient(2)
	client.BaseURL = server.URL

	nodes, enrichable := newNodes()
	client.enrichNodes(nodes, enrichable, &artifactPicker{env: env, allowed: map[packageKey][]string{
		{name: "compiled", version: "1.0"}: {"sdist", "wheel"},
		{name: "foreign", version: "1.0"}:  {"not-on-this-index"},
	}})

	compiled := nodes[packageKey{name: "compiled", version: "1.0"}]
	require.Equal(t, map[int32]string{int32(sbom.HashAlgorithm_SHA256): "wheel"}, compiled.GetHashes())
	require.Equal(t, "https://files.example/pkg-1.0-py3-none-any.whl", compiled.GetUrlDownload())

	single := nodes[packageKey{name: "single", version: "1.0"}]
	require.Equal(t, map[int32]string{int32(sbom.HashAlgorithm_SHA256): "stated"}, single.GetHashes())
	require.Equal(t, "https://as.stated/single.whl", single.GetUrlDownload())

	foreign := nodes[packageKey{name: "foreign", version: "1.0"}]
	require.Empty(t, foreign.GetHashes())
	require.Empty(t, foreign.GetUrlDownload())

	nodes, enrichable = newNodes()
	client.enrichNodes(nodes, enrichable, nil)
	require.Empty(t, nodes[packageKey{name: "compiled", version: "1.0"}].GetHashes())
}

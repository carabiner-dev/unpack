// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package deb

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeDEP5Name(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		// Versioned GNU family: "+" means or-later.
		"GPL-2":     "GPL-2.0-only",
		"GPL-2+":    "GPL-2.0-or-later",
		"GPL-3+":    "GPL-3.0-or-later",
		"LGPL-2.1":  "LGPL-2.1-only",
		"LGPL-2.1+": "LGPL-2.1-or-later",
		"AGPL-3":    "AGPL-3.0-only",
		"GFDL-1.3+": "GFDL-1.3-or-later",
		// DEP-5 names that differ from SPDX.
		"Expat": "MIT",
		// Capitalization fixes via the generic catalog.
		"BSD-2-clause": "BSD-2-Clause",
		"BSD-3-clause": "BSD-3-Clause",
		// Debian-specific names with no SPDX equivalent stay verbatim.
		"public-domain":         "public-domain",
		"BSD-3-clause-Berkeley": "BSD-3-clause-Berkeley",
		"verbatim":              "verbatim",
		// Already-valid SPDX ids pass through.
		"ISC":              "ISC",
		"Unicode-DFS-2016": "Unicode-DFS-2016",
	} {
		assert.Equal(t, want, normalizeDEP5Name(in), in)
	}
}

func TestNormalizeLicenseExpr(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"GPL-2+":                        "GPL-2.0-or-later",
		"BSD-2-clause or GPL-2":         "BSD-2-Clause OR GPL-2.0-only",
		"BSD-3-clause-Berkeley and DEC": "BSD-3-clause-Berkeley AND DEC",
		"ISC and LGPL-2.1+":             "ISC AND LGPL-2.1-or-later",
		"Expat or GPL-2+ or LGPL-2.1":   "MIT OR GPL-2.0-or-later OR LGPL-2.1-only",
	} {
		assert.Equal(t, want, normalizeLicenseExpr(in), in)
	}
}

func TestParseCopyright(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: example

Files: *
Copyright: 2020 Someone
License: GPL-2+

Files: lib/*
Copyright: 2019 Someone Else
License: BSD-2-clause or GPL-2

Files: vendored/*
Copyright: 2018 A Third Person
License: Expat
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software...

License: GPL-2+
 The full text of the GPL-2 follows, as a standalone paragraph that
 must not register a second time.
`)
	licenses, concluded := parseCopyright(in)
	assert.Equal(t, "GPL-2.0-or-later", concluded)
	assert.Equal(t, []string{
		"BSD-2-Clause OR GPL-2.0-only",
		"GPL-2.0-or-later",
		"MIT",
	}, licenses)
}

func TestParseCopyrightHeaderLicenseFallback(t *testing.T) {
	t.Parallel()
	// A header-paragraph License is the umbrella license when no "Files: *"
	// paragraph declares one.
	in := strings.NewReader(`Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
License: ISC

Files: src/*
License: GPL-2
`)
	licenses, concluded := parseCopyright(in)
	assert.Equal(t, "ISC", concluded)
	assert.Equal(t, []string{"GPL-2.0-only", "ISC"}, licenses)
}

func TestParseCopyrightNotDEP5(t *testing.T) {
	t.Parallel()
	// Prose-format copyright files (like base-files in Debian 12) yield
	// nothing, even when their text happens to contain a License: line.
	in := strings.NewReader(`This is the Debian prepackaged version of something.

License: this line is prose, not a deb822 field in a DEP-5 file.
`)
	licenses, concluded := parseCopyright(in)
	assert.Empty(t, licenses)
	assert.Empty(t, concluded)
}

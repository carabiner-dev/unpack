// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	t.Parallel()
	v := Version()
	require.NotEmpty(t, v)
	t.Logf("Embedded SPDX license list version: %s", v)
}

func TestNormalizeAlreadySPDX(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Apache-2.0", Normalize("Apache-2.0", ""))
	require.Equal(t, "MIT", Normalize("MIT", ""))
	require.Equal(t, "GPL-3.0-only", Normalize("GPL-3.0-only", ""))
}

func TestNormalizeByURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		url  string
		want string
	}{
		{"apache", "https://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0"},
		{"apache txt", "http://www.apache.org/licenses/LICENSE-2.0.txt", "Apache-2.0"},
		{"mit", "https://opensource.org/licenses/MIT", "MIT"},
		{"epl", "https://www.eclipse.org/legal/epl-2.0/", "EPL-2.0"},
		{"bsd 3", "https://opensource.org/licenses/BSD-3-Clause", "BSD-3-Clause"},
		{"trailing slash", "https://www.apache.org/licenses/LICENSE-2.0/", "Apache-2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, Normalize("anything", tc.url))
		})
	}
}

func TestNormalizeBySPDXName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want string
	}{
		{"Apache License 2.0", "Apache-2.0"},
		{"MIT License", "MIT"},
		{"BSD 3-Clause \"New\" or \"Revised\" License", "BSD-3-Clause"},
		{"GNU General Public License v2.0 only", "GPL-2.0-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, Normalize(tc.name, ""))
		})
	}
}

func TestNormalizeByCDXMapping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want string
	}{
		// These come from the CycloneDX curated mapping
		{"The Apache Software License, Version 2.0", "Apache-2.0"},
		{"Apache 2.0", "Apache-2.0"},
		{"The MIT License", "MIT"},
		{"Eclipse Public License 2.0", "EPL-2.0"},
		{"Mozilla Public License, Version 2.0", "MPL-2.0"},
		// Dual-license expression
		{"CDDL + GPLv2 with classpath exception", "(CDDL-1.0 OR GPL-2.0-with-classpath-exception)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, Normalize(tc.name, ""))
		})
	}
}

func TestNormalizeURLTakesPrecedence(t *testing.T) {
	t.Parallel()
	require.Equal(t, "MIT", Normalize("Some Random Name", "https://opensource.org/licenses/MIT"))
}

func TestNormalizeUnknown(t *testing.T) {
	t.Parallel()
	require.Equal(t, "My Custom License v42", Normalize("My Custom License v42", ""))
}

func TestNormalizeEmpty(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", Normalize("", ""))
}

func TestNormalizeCaseInsensitive(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Apache-2.0", Normalize("the apache software license, version 2.0", ""))
	require.Equal(t, "Apache-2.0", Normalize("THE APACHE SOFTWARE LICENSE, VERSION 2.0", ""))
}

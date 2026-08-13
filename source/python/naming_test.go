// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeName(t *testing.T) {
	t.Parallel()

	// Every spelling of a name that PEP 503 declares equal maps to the one
	// canonical form.
	for input, expected := range map[string]string{
		"flask":              "flask",
		"Flask":              "flask",
		"typing_extensions":  "typing-extensions",
		"zope.interface":     "zope-interface",
		"ruamel.yaml.clib":   "ruamel-yaml-clib",
		"Sphinx-RTD_theme":   "sphinx-rtd-theme",
		"a.-_b":              "a-b",
		"charset-normalizer": "charset-normalizer",
	} {
		require.Equal(t, expected, NormalizeName(input), "normalizing %q", input)
	}

	// Surrounding whitespace is trimmed before normalizing.
	require.Equal(t, "requests", NormalizeName(" requests "))
}

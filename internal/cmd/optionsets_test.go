// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/stretchr/testify/require"
)

// TestProtobomFormat pins which document each format value writes. A bare
// standard name selects the version unpack writes by default, and moving one
// of those changes what everybody's scripts produce, so it should be a test
// failure rather than a surprise.
func TestProtobomFormat(t *testing.T) {
	t.Parallel()

	for name, expected := range map[string]formats.Format{
		formatSPDX:  formats.SPDX23JSON,
		formatSPDX3: formats.SPDX3JSON,
		formatCDX:   formats.CDX17JSON,
		formatCDXS:  formats.CDX17JSON,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			format, ok := (&formatOptions{Format: name}).ProtobomFormat()
			require.True(t, ok, "%s should be an SBOM format", name)
			require.Equal(t, expected, format)
		})
	}

	// The tree is a view, not a document: it has no protobom format.
	t.Run(formatTree, func(t *testing.T) {
		t.Parallel()
		_, ok := (&formatOptions{Format: formatTree}).ProtobomFormat()
		require.False(t, ok)
	})

	// Every format that can be written has to be one protobom can write.
	t.Run("every sbom format resolves", func(t *testing.T) {
		t.Parallel()
		for _, name := range sbomFormats {
			format, ok := (&formatOptions{Format: name}).ProtobomFormat()
			require.True(t, ok, "%s is listed as an SBOM format but resolves to nothing", name)
			require.Contains(t, formats.List, format, "protobom does not know %s", format)
		}
	})
}

// TestPredicateTypeFor pins the in-toto predicate type each format is
// attested under. SPDX 3 has one of its own: it is a different serialization
// of a different model, so a consumer must be able to tell from the
// statement whether it can read the predicate.
func TestPredicateTypeFor(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		format   formats.Format
		expected string
	}{
		"spdx 3.0.1":    {formats.SPDX3JSON, "https://spdx.dev/Document/v3"},
		"spdx 2.3":      {formats.SPDX23JSON, "https://spdx.dev/Document"},
		"spdx 2.2":      {formats.SPDX22JSON, "https://spdx.dev/Document"},
		"spdx 2.3 tag":  {formats.SPDX23TV, "https://spdx.dev/Document"},
		"cyclonedx 1.7": {formats.CDX17JSON, "https://cyclonedx.org/bom"},
		"cyclonedx 1.4": {formats.CDX14JSON, "https://cyclonedx.org/bom"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			predicateType, err := predicateTypeFor(tc.format)
			require.NoError(t, err)
			require.Equal(t, tc.expected, predicateType)
		})
	}

	// A format that is not an SBOM has nothing to be attested as.
	t.Run("not a format at all", func(t *testing.T) {
		t.Parallel()
		_, err := predicateTypeFor(formats.EmptyFormat)
		require.Error(t, err)
	})

	// Everything the CLI can write can be attested.
	t.Run("every sbom format has a predicate type", func(t *testing.T) {
		t.Parallel()
		for _, name := range sbomFormats {
			format, ok := (&formatOptions{Format: name}).ProtobomFormat()
			require.True(t, ok)
			_, err := predicateTypeFor(format)
			require.NoError(t, err, "%s cannot be attested", name)
		}
	})
}

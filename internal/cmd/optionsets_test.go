// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"slices"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	protosbom "github.com/protobom/protobom/pkg/sbom"
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

// TestParseExtRef pins the TYPE:url form of the --ext-ref flag: the type
// is matched loosely, the url is kept whole however many colons or commas
// it carries, and anything that is not a usable type is refused.
func TestParseExtRef(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		raw      string
		wantType protosbom.ExternalReference_ExternalReferenceType
		wantURL  string
		wantErr  string
	}{
		"uppercase": {
			raw: "VCS:https://github.com/org/repo", wantType: protosbom.ExternalReference_VCS, wantURL: "https://github.com/org/repo",
		},
		"lowercase": {
			raw: "vcs:https://github.com/org/repo", wantType: protosbom.ExternalReference_VCS, wantURL: "https://github.com/org/repo",
		},
		"dashed": {
			raw: "issue-tracker:https://github.com/org/repo/issues", wantType: protosbom.ExternalReference_ISSUE_TRACKER, wantURL: "https://github.com/org/repo/issues",
		},
		"underscored": {
			raw: "ISSUE_TRACKER:https://github.com/org/repo/issues", wantType: protosbom.ExternalReference_ISSUE_TRACKER, wantURL: "https://github.com/org/repo/issues",
		},
		"url with colons and commas": {
			raw: "attestation:https://example.com/a:b?x=1,2", wantType: protosbom.ExternalReference_ATTESTATION, wantURL: "https://example.com/a:b?x=1,2",
		},
		"spaces around": {
			raw: " website : https://example.com ", wantType: protosbom.ExternalReference_WEBSITE, wantURL: "https://example.com",
		},
		"no separator": {raw: "https//example.com", wantErr: "want TYPE:url"},
		"empty type":   {raw: ":https://example.com", wantErr: "want TYPE:url"},
		"empty url":    {raw: "vcs:", wantErr: "no url"},
		"blank url":    {raw: "vcs:  ", wantErr: "no url"},
		"bare url":     {raw: "https://example.com", wantErr: `unknown external reference type "https"`},
		"unknown type": {raw: "nope:https://example.com", wantErr: `unknown external reference type "nope"`},
		"unknown enum": {raw: "unknown:https://example.com", wantErr: `unknown external reference type "unknown"`},
		"empty":        {raw: "", wantErr: "want TYPE:url"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ref, err := parseExtRef(tc.raw)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Nil(t, ref)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantType, ref.GetType())
			require.Equal(t, tc.wantURL, ref.GetUrl())
		})
	}

	// An unknown type names the ones that work, in the form the user types.
	t.Run("error lists the types", func(t *testing.T) {
		t.Parallel()
		_, err := parseExtRef("nope:https://example.com")
		require.ErrorContains(t, err, "issue-tracker")
		require.ErrorContains(t, err, "vcs")
		require.NotContains(t, err.Error(), "unknown,")
	})
}

// TestExtRefTypeNames checks the listing covers protobom's enum, minus the
// zero value, in the dashed lowercase form that round-trips through the
// parser.
func TestExtRefTypeNames(t *testing.T) {
	t.Parallel()
	names := extRefTypeNames()
	require.Len(t, names, len(protosbom.ExternalReference_ExternalReferenceType_value)-1)
	require.True(t, slices.IsSorted(names))
	for _, name := range names {
		require.Equal(t, strings.ToLower(name), name)
		refType, err := parseExtRefType(name)
		require.NoError(t, err, name)
		require.NotEqual(t, protosbom.ExternalReference_UNKNOWN, refType, name)
	}
}

// TestExtRefOptions walks the flag's whole path: the raw values are parsed
// on Validate, every root node of a list gets its own copy of each
// reference on Apply, and non-root nodes are left alone.
func TestExtRefOptions(t *testing.T) {
	t.Parallel()

	t.Run("validate collects every error", func(t *testing.T) {
		t.Parallel()
		eo := &extRefOptions{ExtRefs: []string{"vcs:https://a", "bad", "nope:https://b"}}
		err := eo.Validate()
		require.ErrorContains(t, err, `"bad"`)
		require.ErrorContains(t, err, `"nope:https://b"`)
		require.Len(t, eo.refs, 1)
	})

	t.Run("validate is idempotent", func(t *testing.T) {
		t.Parallel()
		eo := &extRefOptions{ExtRefs: []string{"vcs:https://a"}}
		require.NoError(t, eo.Validate())
		require.NoError(t, eo.Validate())
		require.Len(t, eo.refs, 1)
	})

	t.Run("apply to roots only, one copy each", func(t *testing.T) {
		t.Parallel()
		eo := &extRefOptions{ExtRefs: []string{"vcs:https://a", "website:https://b"}}
		require.NoError(t, eo.Validate())

		nl := &protosbom.NodeList{
			Nodes: []*protosbom.Node{
				{Id: "root1"}, {Id: "root2"}, {Id: "dep"},
			},
			RootElements: []string{"root1", "root2"},
			Edges: []*protosbom.Edge{{
				From: "root1", Type: protosbom.Edge_dependsOn, To: []string{"dep"},
			}},
		}
		eo.Apply(nl)

		root1, root2, dep := nl.GetNodeByID("root1"), nl.GetNodeByID("root2"), nl.GetNodeByID("dep")
		require.Len(t, root1.GetExternalReferences(), 2)
		require.Len(t, root2.GetExternalReferences(), 2)
		require.Empty(t, dep.GetExternalReferences())

		require.Equal(t, protosbom.ExternalReference_VCS, root1.GetExternalReferences()[0].GetType())
		require.Equal(t, "https://a", root1.GetExternalReferences()[0].GetUrl())
		require.Equal(t, protosbom.ExternalReference_WEBSITE, root1.GetExternalReferences()[1].GetType())

		// Copies, not the same message on two nodes
		root1.GetExternalReferences()[0].Comment = "changed"
		require.Empty(t, root2.GetExternalReferences()[0].GetComment())
	})

	t.Run("apply without references is a no-op", func(t *testing.T) {
		t.Parallel()
		eo := &extRefOptions{}
		require.NoError(t, eo.Validate())
		nl := &protosbom.NodeList{Nodes: []*protosbom.Node{{Id: "root"}}, RootElements: []string{"root"}}
		eo.Apply(nl)
		require.Empty(t, nl.GetNodeByID("root").GetExternalReferences())
		eo.Apply(nil)
	})

	t.Run("apply with no roots does nothing", func(t *testing.T) {
		t.Parallel()
		eo := &extRefOptions{ExtRefs: []string{"vcs:https://a"}}
		require.NoError(t, eo.Validate())
		nl := &protosbom.NodeList{Nodes: []*protosbom.Node{{Id: "dep"}}}
		eo.Apply(nl)
		require.Empty(t, nl.GetNodeByID("dep").GetExternalReferences())
	})
}

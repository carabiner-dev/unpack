// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	protosbom "github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestParseEntity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		raw      string
		expected *protosbom.Person
	}{
		{"organization", "Organization: Example Inc", &protosbom.Person{Name: "Example Inc", IsOrg: true}},
		{"person", "Person: Jane Doe", &protosbom.Person{Name: "Jane Doe"}},
		{
			"with an email",
			"Organization: Example Inc (security@example.com)",
			&protosbom.Person{Name: "Example Inc", IsOrg: true, Email: "security@example.com"},
		},
		{
			"a name with a comma",
			"Organization: Example, Inc (security@example.com)",
			&protosbom.Person{Name: "Example, Inc", IsOrg: true, Email: "security@example.com"},
		},
		{
			// SPDX writes "no email" as an empty pair.
			"an empty email",
			"Person: Jane Doe ()",
			&protosbom.Person{Name: "Jane Doe"},
		},
		{
			"a name with parentheses of its own",
			"Organization: Example (UK) Ltd",
			&protosbom.Person{Name: "Example (UK) Ltd", IsOrg: true},
		},
		{
			"a name ending in parentheses, and an email",
			"Organization: Example (UK) (uk@example.com)",
			&protosbom.Person{Name: "Example (UK)", IsOrg: true, Email: "uk@example.com"},
		},
		{
			"a name with a colon",
			"Organization: Example: The Company",
			&protosbom.Person{Name: "Example: The Company", IsOrg: true},
		},
		{
			"another case and spacing",
			"  organization :Example Inc  ( security@example.com ) ",
			&protosbom.Person{Name: "Example Inc", IsOrg: true, Email: "security@example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			person, err := parseEntity("supplier", tc.raw)
			require.NoError(t, err)
			require.Equal(t, tc.expected.GetName(), person.GetName())
			require.Equal(t, tc.expected.GetIsOrg(), person.GetIsOrg())
			require.Equal(t, tc.expected.GetEmail(), person.GetEmail())
		})
	}

	// A value that cannot be read is refused with what is wrong with it,
	// the format wanted and an example, under the flag it was given to.
	for name, tc := range map[string]struct{ raw, problem string }{
		"no kind":              {"Example Inc", "does not say what the name is of"},
		"an unknown kind":      {"Company: Example Inc", `"Company" is neither`},
		"a tool":               {"Tool: unpack", "a tool is neither"},
		"no name":              {"Organization:", "has no name"},
		"only an email":        {"Person: (jane@example.com)", "has no name"},
		"a bad email":          {"Person: Jane Doe (jane@)", "is not an email address"},
		"an email with a name": {"Person: Jane (Jane Doe <jane@example.com>)", "is not an email address"},
		"more than one line":   {"Person: Jane\nDoe", "more than one line"},
		"nothing":              {"", "does not say what the name is of"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parseEntity("author", tc.raw)
			require.Error(t, err)
			require.ErrorContains(t, err, "invalid --author value")
			require.ErrorContains(t, err, tc.problem)
			require.ErrorContains(t, err, entityFormatHelp)
			require.ErrorContains(t, err, "--author "+entityExample)
		})
	}

	// The example the errors and the help give is itself a valid value.
	_, err := parseEntity("supplier", entityExample[1:len(entityExample)-1])
	require.NoError(t, err)
}

func TestEntityOptionsValidate(t *testing.T) {
	t.Parallel()

	t.Run("nothing given", func(t *testing.T) {
		t.Parallel()
		opts := &entityOptions{}
		require.NoError(t, opts.ValidateEntitiesFor(formatTree))
		require.Empty(t, opts.DocumentAuthors())
	})

	t.Run("needs a document to go in", func(t *testing.T) {
		t.Parallel()
		for _, opts := range []*entityOptions{
			{Supplier: "Organization: Example Inc"},
			{Authors: []string{"Person: Jane Doe"}},
		} {
			require.ErrorContains(t, opts.ValidateEntitiesFor(formatTree), "only be named when output set to SPDX or CycloneDX")
			for _, format := range sbomFormats {
				require.NoError(t, opts.ValidateEntitiesFor(format))
			}
			// With no format to speak of, only the values are checked.
			require.NoError(t, opts.Validate())
		}
	})

	t.Run("reports every bad value", func(t *testing.T) {
		t.Parallel()
		opts := &entityOptions{
			Supplier: "Example Inc",
			Authors:  []string{"Person: Jane Doe", "Jane", "Organization: Example Inc (nope@)"},
		}
		err := opts.ValidateEntitiesFor(formatSPDX)
		require.ErrorContains(t, err, `invalid --supplier value "Example Inc"`)
		require.ErrorContains(t, err, `invalid --author value "Jane"`)
		require.ErrorContains(t, err, `invalid --author value "Organization: Example Inc (nope@)"`)
		// The good one is kept.
		require.Len(t, opts.DocumentAuthors(), 1)
	})
}

// TestEntitiesInDocument checks where the supplier and the authors end up:
// the supplier on the root components, in place of any they had, and the
// authors on the document, beside the tools.
func TestEntitiesInDocument(t *testing.T) {
	t.Parallel()

	opts := &entityOptions{
		Supplier: "Organization: Example, Inc (security@example.com)",
		Authors:  []string{"Organization: Example, Inc (sbom@example.com)", "Person: Jane Doe"},
	}
	require.NoError(t, opts.ValidateEntitiesFor(formatSPDX))

	nl := protosbom.NewNodeList()
	root := &protosbom.Node{
		Id: "root", Type: protosbom.Node_PACKAGE, Name: "app", Version: "1.0.0",
		Suppliers: []*protosbom.Person{{Name: "Whoever the manifest named"}},
	}
	dep := &protosbom.Node{Id: "dep", Type: protosbom.Node_PACKAGE, Name: "dep", Version: "2.0.0"}
	nl.AddRootNode(root)
	require.NoError(t, nl.RelateNodeAtID(dep, root.GetId(), protosbom.Edge_dependsOn))

	opts.ApplySupplier(nl)
	require.Len(t, root.GetSuppliers(), 1)
	require.Equal(t, "Example, Inc", root.GetSuppliers()[0].GetName())
	require.True(t, root.GetSuppliers()[0].GetIsOrg())
	require.Equal(t, "security@example.com", root.GetSuppliers()[0].GetEmail())
	require.Empty(t, dep.GetSuppliers(), "a dependency is not the caller's to name the supplier of")

	// No supplier given changes nothing.
	(&entityOptions{}).ApplySupplier(nl)
	require.Len(t, root.GetSuppliers(), 1)

	buf := &bcloser{Buffer: bytes.Buffer{}}
	require.NoError(t, nodeListToSbom(buf, formats.SPDX23JSON, nl, withAuthors(opts.DocumentAuthors())))

	var doc struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			Name     string `json:"name"`
			Supplier string `json:"supplier"`
		} `json:"packages"`
	}
	require.NoError(t, json.Unmarshal(buf.Buffer.Bytes(), &doc))

	require.Contains(t, doc.CreationInfo.Creators, "Organization: Example, Inc (sbom@example.com)")
	require.Contains(t, doc.CreationInfo.Creators, "Person: Jane Doe")
	suppliers := map[string]string{}
	for _, pkg := range doc.Packages {
		suppliers[pkg.Name] = pkg.Supplier
	}
	require.Equal(t, "Organization: Example, Inc (security@example.com)", suppliers["app"])
	require.Empty(t, suppliers["dep"])
}

// TestEntityFlagsOnEverySbomCommand checks that every subcommand that
// writes an SBOM takes the supplier and the authors: whatever the document
// describes, whoever runs the command is its author, and the software it
// is about has a supplier to name.
func TestEntityFlagsOnEverySbomCommand(t *testing.T) {
	t.Parallel()

	root := rootCommand()
	addExtract(root)
	addImage(root)
	addArtifact(root)
	addSBOM(root)
	addRelease(root)

	for _, name := range []string{"extract", "image", "artifact", "sbom", "release"} {
		sub, _, err := root.Find([]string{name})
		require.NoError(t, err)
		require.Equal(t, name, sub.Name())

		supplier := sub.PersistentFlags().Lookup("supplier")
		require.NotNil(t, supplier, "%s has no --supplier", name)
		require.Equal(t, "string", supplier.Value.Type())

		// An array, so that a name with a comma stays one value, and
		// the flag can be given more than once.
		author := sub.PersistentFlags().Lookup("author")
		require.NotNil(t, author, "%s has no --author", name)
		require.Equal(t, "stringArray", author.Value.Type())
	}
}

// TestGenerationContext checks a document says in what contexts its data
// was read, in whatever way its format can: CycloneDX as lifecycle phases,
// SPDX 3 as SBOM types, and SPDX 2, which has no field for it, in the
// document's comment. A document given none says nothing.
func TestGenerationContext(t *testing.T) {
	t.Parallel()

	render := func(t *testing.T, format formats.Format, opts ...documentOption) string {
		t.Helper()
		nl := protosbom.NewNodeList()
		nl.AddRootNode(&protosbom.Node{Id: "root", Type: protosbom.Node_PACKAGE, Name: "app", Version: "1.0.0"})
		buf := &bcloser{Buffer: bytes.Buffer{}}
		require.NoError(t, nodeListToSbom(buf, format, nl, opts...))
		return buf.Buffer.String()
	}

	for name, tc := range map[string]struct {
		contexts  []api.GenerationContext
		spdxTypes string
		cdxPhases []string
		comments  []string
	}{
		"source":   {[]api.GenerationContext{api.ContextSource}, `"source"`, []string{"pre-build"}, []string{"SBOM type: source."}},
		"build":    {[]api.GenerationContext{api.ContextBuild}, `"build"`, []string{"build"}, []string{"SBOM type: build."}},
		"analyzed": {[]api.GenerationContext{api.ContextAnalyzed}, `"analyzed"`, []string{"post-build"}, []string{"SBOM type: analyzed."}},
		// A graph put together from data read in more than one.
		"several": {
			[]api.GenerationContext{api.ContextSource, api.ContextAnalyzed},
			`"source",\s*"analyzed"`,
			[]string{"pre-build", "post-build"},
			[]string{"SBOM type: source.", "SBOM type: analyzed."},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var cdx struct {
				Metadata struct {
					Lifecycles []struct {
						Phase string `json:"phase"`
					} `json:"lifecycles"`
				} `json:"metadata"`
			}
			require.NoError(t, json.Unmarshal([]byte(render(t, formats.CDX17JSON, withContexts(tc.contexts))), &cdx))
			phases := make([]string, 0, len(cdx.Metadata.Lifecycles))
			for _, lifecycle := range cdx.Metadata.Lifecycles {
				phases = append(phases, lifecycle.Phase)
			}
			require.Equal(t, tc.cdxPhases, phases)

			var spdx2 struct {
				Comment string `json:"comment"`
			}
			require.NoError(t, json.Unmarshal([]byte(render(t, formats.SPDX23JSON, withContexts(tc.contexts))), &spdx2))
			for _, comment := range tc.comments {
				require.Contains(t, spdx2.Comment, comment)
			}

			spdx3 := render(t, formats.SPDX3JSON, withContexts(tc.contexts))
			require.Regexp(t, `"software_sbomType":\s*\[\s*`+tc.spdxTypes+`\s*\]`, spdx3)
			require.NotContains(t, spdx3, tc.comments[0], "SPDX 3 states the type itself")
		})
	}

	// Every type there is has its sentence in SPDX 2, and not only the
	// ones unpack reads in itself: a document that is re-read keeps
	// whichever it came with. "Other" names no context to put in words.
	t.Run("every type has its words", func(t *testing.T) {
		t.Parallel()
		for value, name := range protosbom.DocumentType_SBOMType_name {
			generation := api.GenerationContext(value)
			var spdx2 struct {
				Comment string `json:"comment"`
			}
			doc := render(t, formats.SPDX23JSON, withContexts([]api.GenerationContext{generation}))
			require.NoError(t, json.Unmarshal([]byte(doc), &spdx2))
			if generation == protosbom.DocumentType_OTHER {
				require.Empty(t, spdx2.Comment)
				continue
			}
			require.Contains(t, spdx2.Comment, "SBOM type: ", name)
		}
	})

	t.Run("none", func(t *testing.T) {
		t.Parallel()
		var spdx2 struct {
			Comment string `json:"comment"`
		}
		for _, opts := range [][]documentOption{nil, {withContexts(nil)}} {
			require.NoError(t, json.Unmarshal([]byte(render(t, formats.SPDX23JSON, opts...)), &spdx2))
			require.Empty(t, spdx2.Comment)
			require.NotContains(t, render(t, formats.CDX17JSON, opts...), "lifecycles")
		}
	})
}

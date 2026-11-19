// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"

	"github.com/carabiner-dev/command"
	protosbom "github.com/protobom/protobom/pkg/sbom"
	"github.com/spf13/cobra"
)

// This file reads the people and organizations a document names: who
// supplies the software it describes, and who wrote the document. Neither
// can be read off the software, so both are what the caller states, each
// in one value written the way SPDX writes an entity:
//
//	Organization: Example Inc (security@example.com)
//	Person: Jane Doe
//
// The kind, a colon, the name, and optionally an email in parentheses.

const (
	entityKindOrganization = "organization"
	entityKindPerson       = "person"

	// entityFormatHelp states the format, for help texts and errors.
	entityFormatHelp = `"Organization: <name>" or "Person: <name>", optionally followed by an email in parentheses`

	// entityExample is a value in that format.
	entityExample = `"Organization: Example Inc (security@example.com)"`
)

// parseEntity reads a person or organization from its SPDX-like form. The
// flag is the one the value was given to, for the error to name.
func parseEntity(flag, raw string) (*protosbom.Person, error) {
	invalid := func(problem string) error {
		return fmt.Errorf(
			"invalid --%s value %q: %s (want %s, e.g. --%s %s)",
			flag, raw, problem, entityFormatHelp, flag, entityExample,
		)
	}

	if strings.ContainsAny(raw, "\n\r") {
		return nil, invalid("it spans more than one line")
	}

	kind, rest, found := strings.Cut(raw, ":")
	if !found {
		return nil, invalid(`it does not say what the name is of, "Organization:" or "Person:"`)
	}

	person := &protosbom.Person{}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case entityKindOrganization:
		person.IsOrg = true
	case entityKindPerson:
	case "tool":
		return nil, invalid("a tool is neither; the tools that made the document are recorded on their own")
	default:
		return nil, invalid(fmt.Sprintf(`%q is neither "Organization" nor "Person"`, strings.TrimSpace(kind)))
	}

	// The email, when there is one, is the parenthesis the value ends
	// with. A name may carry parentheses of its own, "Example (UK) Ltd",
	// so a closing one that holds no @ is part of the name; an empty
	// pair is how SPDX writes "no email".
	name := strings.TrimSpace(rest)
	if strings.HasSuffix(name, ")") {
		if open := strings.LastIndex(name, "("); open >= 0 {
			inside := strings.TrimSpace(name[open+1 : len(name)-1])
			switch {
			case inside == "":
				name = strings.TrimSpace(name[:open])
			case strings.Contains(inside, "@"):
				address, err := mail.ParseAddress(inside)
				if err != nil || address.Address != inside {
					return nil, invalid(fmt.Sprintf("%q is not an email address", inside))
				}
				person.Email = inside
				name = strings.TrimSpace(name[:open])
			}
		}
	}

	if name == "" {
		return nil, invalid("it has no name")
	}
	person.Name = name
	return person, nil
}

// entityOptions is the reusable options set that names who supplies the
// software an output describes and who authored the document.
type entityOptions struct {
	config *command.OptionsSetConfig

	// Supplier and Authors hold the values as given on the command line.
	Supplier string
	Authors  []string

	supplier *protosbom.Person
	authors  []*protosbom.Person
}

var _ command.OptionsSet = (*entityOptions)(nil)

// Config returns the flag configuration of the entity options.
func (eo *entityOptions) Config() *command.OptionsSetConfig {
	if eo.config == nil {
		eo.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"supplier": {
					Long: "supplier",
					Help: "supplier of the software the output describes, as " + entityFormatHelp +
						" (e.g. " + entityExample + "); needs an SBOM format",
				},
				"author": {
					Long: "author",
					Help: "author of the SBOM document, in the same form as --supplier; repeatable, needs an SBOM format",
				},
			},
		}
	}
	return eo.config
}

// AddFlags adds the supplier and author flags to a command. The authors
// are an array, not a slice: names carry commas, "Example, Inc", so each
// value stays whole.
func (eo *entityOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&eo.Supplier, eo.Config().LongFlag("supplier"), "", eo.Config().HelpText("supplier"),
	)
	cmd.PersistentFlags().StringArrayVar(
		&eo.Authors, eo.Config().LongFlag("author"), nil, eo.Config().HelpText("author"),
	)
}

// Validate parses the values, so a bad one fails before any work.
func (eo *entityOptions) Validate() error {
	return eo.ValidateEntitiesFor("")
}

// ValidateEntitiesFor parses the values and checks they have somewhere to
// go: the tree view shows neither, so naming them with it is a mistake.
// An empty format skips the check, for callers that have no format.
func (eo *entityOptions) ValidateEntitiesFor(format string) error {
	eo.supplier, eo.authors = nil, nil
	errs := []error{}

	if (eo.Supplier != "" || len(eo.Authors) > 0) && format != "" && !slices.Contains(sbomFormats, format) {
		errs = append(errs, errors.New("a supplier and authors can only be named when output set to SPDX or CycloneDX"))
	}

	if eo.Supplier != "" {
		supplier, err := parseEntity("supplier", eo.Supplier)
		if err != nil {
			errs = append(errs, err)
		}
		eo.supplier = supplier
	}
	for _, raw := range eo.Authors {
		author, err := parseEntity("author", raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		eo.authors = append(eo.authors, author)
	}
	return errors.Join(errs...)
}

// ApplySupplier names the supplier on every root node of the list, in
// place of any it has: the caller's word is the last one. Each node gets
// its own copy.
func (eo *entityOptions) ApplySupplier(nl *protosbom.NodeList) {
	if eo.supplier == nil || nl == nil {
		return
	}
	roots := nl.GetRootNodes()
	if len(roots) == 0 {
		cliLog().Warn("no root components to name the supplier of")
		return
	}
	for _, n := range roots {
		n.Suppliers = []*protosbom.Person{eo.supplier.Copy()}
	}
}

// DocumentAuthors returns the authors to name on a document, each a copy.
func (eo *entityOptions) DocumentAuthors() []*protosbom.Person {
	authors := make([]*protosbom.Person, 0, len(eo.authors))
	for _, author := range eo.authors {
		authors = append(authors, author.Copy())
	}
	return authors
}

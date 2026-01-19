// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/unpack/dependencies"
)

const (
	codebasesFormatTable = "table"
	codebasesFormatJSON  = "json"
)

var validCodebasesFormats = []string{codebasesFormatTable, codebasesFormatJSON}

type codebasesOptions struct {
	Path           string
	IgnorePatterns []string
	Format         string
}

// Validate validates the options in context with arguments
func (o *codebasesOptions) Validate() error {
	errs := []error{}
	if o.Path == "" {
		errs = append(errs, errors.New("path not defined"))
	}

	if !slices.Contains(validCodebasesFormats, o.Format) {
		errs = append(errs, fmt.Errorf("invalid format, must be one of: %v", validCodebasesFormats))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (o *codebasesOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&o.Path, "path", "p", "", "path to scan for codebases",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.IgnorePatterns, "ignore", "i", []string{}, "path patterns to ignore from scanning",
	)

	cmd.PersistentFlags().StringVarP(
		&o.Format, "format", "f", codebasesFormatTable, fmt.Sprintf("output format %v", validCodebasesFormats),
	)
}

func addLs(parent *cobra.Command) {
	opts := &codebasesOptions{}

	lsCmd := &cobra.Command{
		Short: "list discovered codebases in a path",
		Long: fmt.Sprintf(`%s ls: list discovered codebases

Scans a directory for codebases and lists them with IDs that can be used
with the extract command's --codebase flag to target specific codebases.

The ID format is: <language>:<relative-path>
Examples:
  golang:.              (root directory Go project)
  golang:services/api
  rust:tools/parser
  npm:frontend

`, appname),
		Use:               "ls [flags] path",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Path = args[0]
			}

			if opts.Path == "" {
				opts.Path = "."
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			return listCodebases(cmd.Context(), opts)
		},
	}

	opts.AddFlags(lsCmd)
	parent.AddCommand(lsCmd)
}

func listCodebases(ctx context.Context, opts *codebasesOptions) error {
	unpacker := dependencies.NewUnpacker()
	unpacker.Options.IgnorePatterns = opts.IgnorePatterns

	codebases, err := unpacker.ListCodebases(ctx, opts.Path)
	if err != nil {
		return fmt.Errorf("listing codebases: %w", err)
	}

	if len(codebases) == 0 {
		fmt.Fprintln(os.Stderr, "No codebases found")
		return nil
	}

	switch opts.Format {
	case codebasesFormatTable:
		return outputCodebasesTable(codebases)
	case codebasesFormatJSON:
		return outputCodebasesJSON(codebases)
	default:
		return fmt.Errorf("invalid format: %s", opts.Format)
	}
}

func outputCodebasesTable(codebases []dependencies.CodebaseInfo) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tLANGUAGE\tPATH") //nolint:errcheck
	for _, cb := range codebases {
		fmt.Fprintf(w, "%s\t%s\t%s\n", cb.ID, cb.Language, cb.Path) //nolint:errcheck
	}
	return w.Flush()
}

type codebaseJSONOutput struct {
	Codebases []codebaseJSON `json:"codebases"`
}

type codebaseJSON struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Path     string `json:"path"`
}

func outputCodebasesJSON(codebases []dependencies.CodebaseInfo) error {
	output := codebaseJSONOutput{
		Codebases: make([]codebaseJSON, len(codebases)),
	}
	for i, cb := range codebases {
		output.Codebases[i] = codebaseJSON{
			ID:       cb.ID,
			Language: cb.Language,
			Path:     cb.Path,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

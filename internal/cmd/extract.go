// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/protograph"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/unpack/dependencies"
)

const (
	formatSPDX = "spdx"
	formatCDX  = "cyclonedx"
)

type extractOptions struct {
	IgnorePatterns       []string
	Path                 string
	Format               string
	IndexFiles           bool
	Attest               bool
	IgnoreExtraCodebases bool
	Codebase             string
}

var validFormats = []string{formatSPDX, formatCDX, "cdx", "tree"}

// Validates the options in context with arguments
func (ro *extractOptions) Validate() error {
	errs := []error{}
	if ro.Path == "" {
		errs = append(errs, errors.New("path not defined"))
	}

	if !slices.Contains(validFormats, ro.Format) {
		errs = append(errs, errors.New("invalid format"))
	}

	if ro.Attest && (ro.Format != formatSPDX && ro.Format != formatCDX) {
		errs = append(errs, fmt.Errorf("attestations can only be generated when output set to SPDX or CycloneDX"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *extractOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&ro.Path, "path", "p", "", "path to the artifact to unpack",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&ro.IgnorePatterns, "ignore", "i", []string{}, "path patterns to ignore from analysis and indexing",
	)

	cmd.PersistentFlags().StringVarP(
		&ro.Format, "format", "f", "tree", fmt.Sprintf("format for the output %+v", validFormats),
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IndexFiles, "files", true, "Index all files in codebases",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.Attest, "attest", false, "output sboms in an intoto attestation",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IgnoreExtraCodebases, "ignore-other-codebases", false, "don't fail if more than one codebase found",
	)

	cmd.PersistentFlags().StringVarP(
		&ro.Codebase, "codebase", "c", "", "extract only a specific codebase by ID (e.g., 'golang:services/api')",
	)
}

func addExtract(parent *cobra.Command) {
	opts := &extractOptions{}

	extractCmd := &cobra.Command{
		Short: "read dependency data from codebases, artifacts and more",
		Long: fmt.Sprintf(`%s: dependency data extractor

Unpack extract takes a dependency source as an argument and applies a decomposer
to read its dependency data.

By default, dependencies are displayed as an ASCII tree in the terminal but 
the data can be exported as JSON or an SPDX or CycloneDX sbom.

Usage patterns:
  %[1]s extract /path/to/project           Extract from a specific path
  %[1]s extract golang:.                   Extract using codebase ID (path defaults to .)
  %[1]s extract --codebase=golang:.        Same as above, using flag
  %[1]s extract -c rust:tools/parser       Filter to specific codebase in current directory

When a codebase ID is provided (format: language:path), the search path defaults
to the current directory.

`, appname),
		Use:               "extract [flags] [path | codebase-id]",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				arg := args[0]
				// Check if the argument looks like a codebase ID
				// (contains a language, ":" and a relative path)
				if looksLikeCodebaseID(arg) {
					// Treat as codebase ID, default path to current directory
					opts.Codebase = arg
					if opts.Path == "" {
						opts.Path = "."
					}
				} else {
					// Treat as path
					opts.Path = arg
				}
			}

			// If --codebase is set but no path, default to current directory
			if opts.Codebase != "" && opts.Path == "" {
				opts.Path = "."
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			unpacker := dependencies.NewUnpacker()

			// Add all the source files from codebases
			unpacker.Options.IndexFiles = opts.IndexFiles

			// Add any extra paths to ignore
			unpacker.Options.IgnorePatterns = opts.IgnorePatterns
			///unpacker.Options.UseGitIgnore = opts.UseGitIgnore

			unpacker.Options.FailOnSingleMulti = !opts.IgnoreExtraCodebases

			// Filter to a specific codebase if provided
			unpacker.Options.CodebaseFilter = opts.Codebase

			// Run the extract process:
			nodelist, err := unpacker.ExtractCodebase(opts.Path)
			if err != nil {
				// .. if it failed because there is more than one codebase,
				//  show the users the found codebases
				if errors.Is(err, dependencies.ErrMultipleCodebases) {
					fmt.Fprintf(os.Stderr, "Error: Multiple codebases found:\n")
					return listCodebases(cmd.Context(), &codebasesOptions{
						Path:           opts.Path,
						IgnorePatterns: opts.IgnorePatterns,
						Format:         codebasesFormatTable,
					})
				}
				return err
			}

			if nodelist == nil {
				return errors.New("no dependency data found")
			}

			var format formats.Format

			switch opts.Format {
			case "tree":
				pg := protograph.New()
				if err := pg.GraphNodeList(nodelist); err != nil {
					return err
				}
				return nil
			case formatSPDX:
				format = formats.SPDX23JSON
			case "cdx", formatCDX:
				format = formats.CDX16JSON
			default:
				return fmt.Errorf("invalid format")
			}

			if opts.Attest {
				err = nodeListToAttestation(os.Stdout, format, nodelist)
			} else {
				err = nodeListToSbom(os.Stdout, format, nodelist)
			}

			if err != nil {
				return fmt.Errorf("rendering SBOM: %w", err)
			}

			return nil
		},
	}

	opts.AddFlags(extractCmd)
	parent.AddCommand(extractCmd)
}

// looksLikeCodebaseID checks if the argument appears to be a codebase ID.
// A codebase ID has the format "language:path" where language is a known decomposer.
func looksLikeCodebaseID(arg string) bool {
	language, path, found := strings.Cut(arg, ":")
	if !found {
		return false
	}

	// Must have both language and path parts
	if language == "" || path == "" {
		return false
	}

	return true
}

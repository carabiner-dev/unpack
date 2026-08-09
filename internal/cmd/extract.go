// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/carabiner-dev/protograph"
	"github.com/carabiner-dev/signer"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/dependencies"
)

const (
	// The SBOM formats the output can be written in. A bare name selects
	// the version of that standard unpack writes by default; SPDX 3 is a
	// name of its own so that a caller asking for "spdx" keeps getting the
	// SPDX 2.3 it has always got.
	formatSPDX  = "spdx"
	formatSPDX3 = "spdx3"
	formatCDX   = "cyclonedx"
	formatCDXS  = "cdx"
	formatTree  = "tree"
)

type extractOptions struct {
	formatOptions
	filesOptions
	IgnorePatterns       []string
	Path                 string
	Networking           string
	IgnoreExtraCodebases bool
	MultipleOutputs      bool
	IncludeDev           bool
	IncludeBuild         bool
	IncludeOptional      bool
	Codebase             string
	OutputPath           string
	OutputPrefix         string
}

var validFormats = []string{formatSPDX, formatSPDX3, formatCDX, formatCDXS, formatTree}

// sbomFormats are the formats that produce a document, as opposed to the
// tree view. Only these can be attested.
var sbomFormats = []string{formatSPDX, formatSPDX3, formatCDX, formatCDXS}

// Validates the options in context with arguments
func (ro *extractOptions) Validate() error {
	errs := []error{
		ro.formatOptions.Validate(),
		ro.filesOptions.Validate(),
	}
	if ro.Path == "" {
		errs = append(errs, errors.New("path not defined"))
	}

	if !slices.Contains([]string{"essential", "full", "disabled"}, ro.Networking) {
		errs = append(errs, fmt.Errorf("invalid networking level %q (must be essential, full, or disabled)", ro.Networking))
	}

	// Tree view can handle only one codebase
	if ro.Format == formatTree && ro.MultipleOutputs {
		errs = append(errs, errors.New("cannot specify multi and tree view at the same time"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *extractOptions) AddFlags(cmd *cobra.Command) {
	ro.formatOptions.AddFlags(cmd)
	ro.filesOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVarP(
		&ro.Path, "path", "p", ".", "path to the artifact to unpack",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&ro.IgnorePatterns, "ignore", "i", []string{}, "path patterns to ignore from analysis and indexing",
	)

	cmd.PersistentFlags().StringVar(
		&ro.Networking, "networking", "essential",
		"network access level: essential (default), full, or disabled",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IncludeDev, "include-dev", false, "include development/test dependencies",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IncludeBuild, "include-build", false, "include build tool dependencies",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IncludeOptional, "include-optional", false, "include optional dependencies",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IgnoreExtraCodebases, "ignore-other-codebases", false, "don't fail if more than one codebase found",
	)

	cmd.PersistentFlags().StringVarP(
		&ro.Codebase, "codebase", "c", "", "extract only a specific codebase by ID (e.g., 'golang:services/api')",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.MultipleOutputs, "multi", false, "extract all codebases independently",
	)

	cmd.PersistentFlags().StringVarP(
		&ro.OutputPath, "output", "o", "", "directory to write the output to (defaults to STDOUT)",
	)

	cmd.PersistentFlags().StringVar(
		&ro.OutputPrefix, "output-prefix", "", "prefix to prepend to generated filenames before codebase id",
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
  %[1]s extract --multi -f spdx            Extract all codebases as separate SPDX SBOMs
  %[1]s extract --multi -o sboms/          Write each codebase SBOM to a file in sboms/
  %[1]s extract --multi -o sboms/ --output-prefix myproject-
                                           Prepend "myproject-" to each output filename

When a codebase ID is provided (format: language:path), the search path defaults
to the current directory.

`, appname),
		Use:               "extract [flags] [path | codebase-id]",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				arg := args[0]
				// Check if the argument looks like a codebase ID
				// (contains a language, ":" and a relative path)
				if looksLikeCodebaseID(arg) {
					// Treat as codebase ID, default path to current directory
					opts.Codebase = arg
				} else {
					// Treat as path
					opts.Path = arg
				}
			}

			// If --codebase is set but no path, default to current directory
			if opts.Codebase != "" && opts.Path == "" {
				opts.Path = "."
			}

			// Default to SPDX when --attest or --sign is used and
			// --format was not explicitly specified.
			opts.DefaultToSPDX(cmd)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			unpacker := dependencies.NewUnpacker()

			// Add all the source files from codebases
			unpacker.Options.IndexFiles = opts.Files

			// Add any extra paths to ignore
			unpacker.Options.IgnorePatterns = opts.IgnorePatterns
			///unpacker.Options.UseGitIgnore = opts.UseGitIgnore

			// If we only intend to extract a single codebase, and there are many,
			// we can ignore the others:
			unpacker.Options.FailOnSingleMulti = !opts.IgnoreExtraCodebases

			// Filter to a specific codebase if provided
			unpacker.Options.CodebaseFilter = opts.Codebase

			// Set dependency inclusion options
			unpacker.Options.IncludeDev = opts.IncludeDev
			unpacker.Options.IncludeBuild = opts.IncludeBuild
			unpacker.Options.IncludeOptional = opts.IncludeOptional

			// Set networking level
			switch opts.Networking {
			case "full":
				unpacker.Options.Networking = api.NetworkFull
			case "disabled":
				unpacker.Options.Networking = api.NetworkDisabled
			default:
				unpacker.Options.Networking = api.NetworkEssential
			}

			// Ensure the output directory exists when writing to files
			if opts.OutputPath != "" {
				if err := os.MkdirAll(opts.OutputPath, os.FileMode(0o755)); err != nil {
					return fmt.Errorf("creating output directory: %w", err)
				}
			}

			codebases, err := unpacker.ListCodebases(cmd.Context(), opts.Path)
			if err != nil {
				return fmt.Errorf("listing codebases: %w", err)
			}

			// If a specific codebase was requested, filter to just that one
			if opts.Codebase != "" {
				var filtered []dependencies.CodebaseInfo
				for _, cb := range codebases {
					if cb.ID == opts.Codebase {
						filtered = append(filtered, cb)
						break
					}
				}
				if len(filtered) == 0 {
					fmt.Fprintln(os.Stderr)
					fmt.Fprintf(os.Stderr, "%s codebase %q not found.\n", color.RedString("Error:"), opts.Codebase)
					fmt.Fprintln(os.Stderr, "Available codebases:")
					fmt.Fprintln(os.Stderr)
					return listCodebases(cmd.Context(), &codebasesOptions{
						Path:           opts.Path,
						IgnorePatterns: opts.IgnorePatterns,
						Format:         codebasesFormatTable,
					})
				}
				codebases = filtered
			}

			// Lets handle the cases here
			if len(codebases) == 0 {
				return errors.New("no codebases found in specified path")
			}

			if len(codebases) > 1 {
				if !opts.IgnoreExtraCodebases && !opts.MultipleOutputs {
					fmt.Fprintln(os.Stderr)
					fmt.Fprintf(os.Stderr, "%s Multiple codebases found.\n", color.RedString("Error:"))
					fmt.Fprintln(os.Stderr, "Run unpack extract <codebase ID>")
					fmt.Fprintln(os.Stderr)
					return listCodebases(cmd.Context(), &codebasesOptions{
						Path:           opts.Path,
						IgnorePatterns: opts.IgnorePatterns,
						Format:         codebasesFormatTable,
					})
				}
			}

			// Create the signer once if --sign is enabled so that the
			// OIDC flow is not repeated for each codebase.
			var s *signer.Signer
			if opts.Sign {
				s = signer.NewSigner()
			}

			for _, cb := range codebases {
				if err := handleCodeBase(cmd.Context(), opts, s, unpacker, cb.ID); err != nil {
					return err
				}
			}

			return nil
		},
	}

	opts.AddFlags(extractCmd)
	parent.AddCommand(extractCmd)
}

func handleCodeBase(ctx context.Context, opts *extractOptions, s *signer.Signer, unpacker *dependencies.Unpacker, id string) error {
	// Set the codebase filter to target this specific codebase and
	// extract using the base path (not the codebase ID).
	unpacker.Options.CodebaseFilter = id
	nodelist, err := unpacker.ExtractCodebaseWithContext(ctx, opts.Path)
	if err != nil {
		// .. if it failed because there is more than one codebase,
		//  show the users the found codebases
		if errors.Is(err, dependencies.ErrMultipleCodebases) {
			fmt.Fprintf(os.Stderr, "%s Multiple codebases found:\n", color.RedString("Error:"))
			return listCodebases(ctx, &codebasesOptions{
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

	format, isSbom := opts.ProtobomFormat()
	if !isSbom {
		pg := protograph.New()
		if err := pg.GraphNodeList(nodelist); err != nil {
			return err
		}
		return nil
	}

	// Determine the output writer. When an output directory is set,
	// write each codebase to its own file. Otherwise write to stdout.
	var wr io.WriteCloser
	if opts.OutputPath != "" {
		filename := codebaseOutputFilename(opts, id)
		p := filepath.Join(opts.OutputPath, filename)
		f, err := os.Create(p)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", p, err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "error closing %s: %v\n", p, cerr)
			}
		}()
		wr = f
		fmt.Fprintf(os.Stderr, "%s\n", p)
	} else {
		wr = os.Stdout
	}

	switch {
	case opts.Sign:
		err = nodeListToSignedAttestation(s, wr, format, nodelist)
	case opts.Attest:
		err = nodeListToAttestation(wr, format, nodelist)
	default:
		err = nodeListToSbom(wr, format, nodelist)
	}

	if err != nil {
		return fmt.Errorf("rendering SBOM: %w", err)
	}
	return nil
}

// codebaseOutputFilename generates the output filename for a codebase ID.
// The ID (e.g. "golang:source/api") is sanitized by replacing colons and
// slashes with dashes and the appropriate extension is appended.
func codebaseOutputFilename(opts *extractOptions, id string) string {
	// Determine extension from format
	var ext string
	switch opts.Format {
	case formatSPDX:
		ext = ".spdx.json"
	case formatCDXS, formatCDX:
		ext = ".cdx.json"
	default:
		ext = ".json"
	}

	// Sanitize the codebase ID: replace colons and slashes with dashes
	sanitized := strings.ReplaceAll(id, ":", "-")
	sanitized = strings.ReplaceAll(sanitized, "/", "-")

	// Strip trailing dash from IDs like "golang:." which become "golang-."
	sanitized = strings.TrimSuffix(sanitized, "-.")
	sanitized = strings.TrimSuffix(sanitized, ".")

	return opts.OutputPrefix + sanitized + ext
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

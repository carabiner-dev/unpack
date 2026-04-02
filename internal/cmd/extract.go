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
	MultipleOutputs      bool
	Codebase             string
	OutputPath           string
	OutputPrefix         string
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

	// Tree view can handle only one codebase
	if ro.Format == "tree" && ro.MultipleOutputs {
		errs = append(errs, errors.New("cannot specify multi and tree view at the same time"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *extractOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&ro.Path, "path", "p", ".", "path to the artifact to unpack",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&ro.IgnorePatterns, "ignore", "i", []string{}, "path patterns to ignore from analysis and indexing",
	)

	cmd.PersistentFlags().StringVarP(
		&ro.Format, "format", "f", "tree", fmt.Sprintf("format for the output %+v", validFormats),
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IndexFiles, "files", dependencies.DefaultOptions.IndexFiles, "Index all files in codebases",
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
		PreRunE: func(_ *cobra.Command, args []string) error {
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

			// If we only intend to extract a single codebase, and there are many,
			// we can ignore the others:
			unpacker.Options.FailOnSingleMulti = !opts.IgnoreExtraCodebases

			// Filter to a specific codebase if provided
			unpacker.Options.CodebaseFilter = opts.Codebase

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

			// Lets handle the cases here
			if len(codebases) == 0 {
				return errors.New("no codebases found in specified path")
			}

			if len(codebases) > 1 {
				if !opts.IgnoreExtraCodebases && !opts.MultipleOutputs {
					fmt.Fprintf(os.Stderr, "Error: Multiple codebases found:\n")
					return listCodebases(cmd.Context(), &codebasesOptions{
						Path:           opts.Path,
						IgnorePatterns: opts.IgnorePatterns,
						Format:         codebasesFormatTable,
					})
				}
			}

			for _, cb := range codebases {
				if err := handleCodeBase(cmd.Context(), opts, unpacker, cb.ID); err != nil {
					return err
				}
			}

			return nil
		},
	}

	opts.AddFlags(extractCmd)
	parent.AddCommand(extractCmd)
}

func handleCodeBase(ctx context.Context, opts *extractOptions, unpacker *dependencies.Unpacker, id string) error {
	// Set the codebase filter to target this specific codebase and
	// extract using the base path (not the codebase ID).
	unpacker.Options.CodebaseFilter = id
	nodelist, err := unpacker.ExtractCodebaseWithContext(ctx, opts.Path)
	if err != nil {
		// .. if it failed because there is more than one codebase,
		//  show the users the found codebases
		if errors.Is(err, dependencies.ErrMultipleCodebases) {
			fmt.Fprintf(os.Stderr, "Error: Multiple codebases found:\n")
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
		defer f.Close()
		wr = f
		fmt.Fprintf(os.Stderr, "%s\n", p)
	} else {
		wr = os.Stdout
	}

	if opts.Attest {
		err = nodeListToAttestation(wr, format, nodelist)
	} else {
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
	case "cdx", formatCDX:
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

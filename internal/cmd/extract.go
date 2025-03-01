// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/carabiner-dev/protograph"
	"github.com/carabiner-dev/unpack/dependencies"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/spf13/cobra"
)

type extractOptions struct {
	Path       string
	Format     string
	IndexFiles bool
	Attest     bool
}

var validFormats = []string{"spdx", "cyclonedx", "cdx", "tree"}

// Validates the options in context with arguments
func (ro *extractOptions) Validate() error {
	errs := []error{}
	if ro.Path == "" {
		errs = append(errs, errors.New("path not defined"))
	}

	if !slices.Contains(validFormats, ro.Format) {
		errs = append(errs, errors.New("invalid format"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *extractOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&ro.Path, "path", "p", "", "path to the artifact to unpack",
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
}

func addExtract(parent *cobra.Command) {
	opts := &extractOptions{}

	var extractCmd = &cobra.Command{
		Short: "read dependency data from codebases, artifacts and more",
		Long: fmt.Sprintf(`%s: dependency data extractor

Unpack extract takes a dependency source as an argument and applies a decomposer
to read its dependency data. 

`, appname),
		Use:               "extract [flags] source",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Path = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			unpacker := dependencies.NewUnpacker()

			// Add all the source files from codebases
			unpacker.Options.IndexFiles = true

			nodelist, err := unpacker.ExtractCodebase(opts.Path)

			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			if nodelist == nil {
				fmt.Fprintln(os.Stderr, "No dependency data found")
				os.Exit(1)
			}

			var format formats.Format

			switch opts.Format {
			case "tree":
				pg := protograph.New()
				if err := pg.GraphNodeList(nodelist); err != nil {
					return err
				}
				return nil
			case "spdx":
				format = formats.SPDX23JSON
			case "cdx", "cyclonedx":
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

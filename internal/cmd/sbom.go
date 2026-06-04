// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/carabiner-dev/protograph"
	"github.com/carabiner-dev/signer"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/spf13/cobra"

	sbomunpack "github.com/carabiner-dev/unpack/sbom"
)

type sbomOptions struct {
	Path            string
	Format          string
	Attest          bool
	Sign            bool
	IncludeDev      bool
	IncludeBuild    bool
	IncludeOptional bool
}

// Validates the options in context with arguments
func (ro *sbomOptions) Validate() error {
	errs := []error{}
	if ro.Path == "" {
		errs = append(errs, errors.New("path not defined"))
	}

	if !slices.Contains(validFormats, ro.Format) {
		errs = append(errs, errors.New("invalid format"))
	}

	// --sign implies --attest
	if ro.Sign {
		ro.Attest = true
	}

	if ro.Attest && (ro.Format != formatSPDX && ro.Format != formatCDX) {
		errs = append(errs, fmt.Errorf("attestations can only be generated when output set to SPDX or CycloneDX"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *sbomOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&ro.Path, "path", "p", "", "path to the sbom file",
	)

	cmd.PersistentFlags().StringVarP(
		&ro.Format, "format", "f", formatTree, fmt.Sprintf("format for the output %+v", validFormats),
	)

	cmd.PersistentFlags().BoolVar(
		&ro.Attest, "attest", false, "output sboms in an intoto attestation",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.Sign, "sign", false, "sign the attestation into a sigstore bundle (implies --attest)",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IncludeDev, "include-dev", true, "include development/test dependencies (default: true for SBOM reading)",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IncludeBuild, "include-build", true, "include build tool dependencies (default: true for SBOM reading)",
	)

	cmd.PersistentFlags().BoolVar(
		&ro.IncludeOptional, "include-optional", true, "include optional dependencies (default: true for SBOM reading)",
	)
}

func addSBOM(parent *cobra.Command) {
	opts := &sbomOptions{}

	extractCmd := &cobra.Command{
		Short: "read dependency data from an SBOM",
		Long: fmt.Sprintf(`%s: dependency data extractor

Unpack sbom takes an SBOM document and returns dependency data from its contents.

`, appname),
		Use:               "sbom [flags] source",
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
			unpacker := sbomunpack.NewUnpacker()

			nodelists, err := unpacker.Extract(cmd.Context(), &sbomunpack.Subject{Path: opts.Path})
			if err != nil {
				return err
			}

			if len(nodelists) == 0 || nodelists[0] == nil {
				return errors.New("no dependency data found")
			}
			nodelist := nodelists[0]

			// Filter out excluded dependency types
			filterNodeListByEdgeType(nodelist, opts)

			var format formats.Format

			switch opts.Format {
			case formatTree:
				pg := protograph.New()
				if err := pg.GraphNodeList(nodelist); err != nil {
					return err
				}
				return nil
			case formatSPDX:
				format = formats.SPDX23JSON
			case formatCDXS, formatCDX:
				format = formats.CDX16JSON
			default:
				return fmt.Errorf("invalid format")
			}

			switch {
			case opts.Sign:
				s := signer.NewSigner()
				err = nodeListToSignedAttestation(s, os.Stdout, format, nodelist)
			case opts.Attest:
				err = nodeListToAttestation(os.Stdout, format, nodelist)
			default:
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

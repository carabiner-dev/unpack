// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"

	"github.com/carabiner-dev/command"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/spf13/cobra"
)

// formatOptions is the reusable options set controlling how extracted
// dependency data is rendered: the output format plus the attestation and
// signing toggles, whose validation rules are coupled to it.
type formatOptions struct {
	config *command.OptionsSetConfig

	// Format selects the output rendering: an ASCII tree or an SBOM format.
	Format string

	// Attest wraps the resulting SBOM in an in-toto attestation.
	Attest bool

	// Sign signs the attestation into a sigstore bundle (implies Attest).
	Sign bool
}

var _ command.OptionsSet = (*formatOptions)(nil)

// Config returns the flag configuration of the format options.
func (fo *formatOptions) Config() *command.OptionsSetConfig {
	if fo.config == nil {
		fo.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"format": {
					Short: "f",
					Long:  "format",
					Help:  fmt.Sprintf("format for the output %+v", validFormats),
				},
				"attest": {
					Long: "attest",
					Help: "output sboms in an intoto attestation (defaults to format=spdx)",
				},
				"sign": {
					Long: "sign",
					Help: "sign the attestation into a sigstore bundle (implies --attest)",
				},
			},
		}
	}
	return fo.config
}

// AddFlags adds the format, attest and sign flags to a command.
func (fo *formatOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&fo.Format, fo.Config().LongFlag("format"), fo.Config().ShortFlag("format"),
		formatTree, fo.Config().HelpText("format"),
	)
	cmd.PersistentFlags().BoolVar(
		&fo.Attest, fo.Config().LongFlag("attest"), false, fo.Config().HelpText("attest"),
	)
	cmd.PersistentFlags().BoolVar(
		&fo.Sign, fo.Config().LongFlag("sign"), false, fo.Config().HelpText("sign"),
	)
}

// Validate checks the format options, applying the --sign implies --attest
// rule.
func (fo *formatOptions) Validate() error {
	errs := []error{}
	if !slices.Contains(validFormats, fo.Format) {
		errs = append(errs, errors.New("invalid format"))
	}

	// --sign implies --attest
	if fo.Sign {
		fo.Attest = true
	}

	if fo.Attest && (fo.Format != formatSPDX && fo.Format != formatCDX && fo.Format != formatCDXS) {
		errs = append(errs, errors.New("attestations can only be generated when output set to SPDX or CycloneDX"))
	}
	return errors.Join(errs...)
}

// DefaultToSPDX switches the format to SPDX when attesting or signing was
// requested but no explicit format was chosen. Call it from PreRun, where
// the flag change state is known.
func (fo *formatOptions) DefaultToSPDX(cmd *cobra.Command) {
	flag := fo.Config().LongFlag("format")
	if (fo.Attest || fo.Sign) &&
		!cmd.Flags().Changed(flag) && !cmd.PersistentFlags().Changed(flag) {
		fo.Format = formatSPDX
	}
}

// ProtobomFormat translates the format selection to a protobom serializer
// format. The boolean reports whether the selection is an SBOM format at
// all — the tree view returns false.
func (fo *formatOptions) ProtobomFormat() (formats.Format, bool) {
	switch fo.Format {
	case formatSPDX:
		return formats.SPDX23JSON, true
	case formatCDX, formatCDXS:
		return formats.CDX16JSON, true
	default:
		return "", false
	}
}

// filesOptions is the reusable options set controlling file indexing: when
// enabled, the files of the unpacked subject are included in the resulting
// dependency data.
type filesOptions struct {
	config *command.OptionsSetConfig

	// Files includes the subject's files in the extracted data.
	Files bool
}

var _ command.OptionsSet = (*filesOptions)(nil)

// Config returns the flag configuration of the files options.
func (fo *filesOptions) Config() *command.OptionsSetConfig {
	if fo.config == nil {
		fo.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"files": {
					Long: "files",
					Help: "include all files in the extracted dependency data",
				},
			},
		}
	}
	return fo.config
}

// AddFlags adds the files flag to a command.
func (fo *filesOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&fo.Files, fo.Config().LongFlag("files"), false, fo.Config().HelpText("files"),
	)
}

// Validate checks the files options.
func (fo *filesOptions) Validate() error { return nil }

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"

	"github.com/carabiner-dev/command"
	"github.com/protobom/protobom/pkg/formats"
	protosbom "github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/stitch"
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
					Help: "output sboms in an intoto attestation (defaults to format=spdx3)",
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

	if fo.Attest && !slices.Contains(sbomFormats, fo.Format) {
		errs = append(errs, errors.New("attestations can only be generated when output set to SPDX or CycloneDX"))
	}
	return errors.Join(errs...)
}

// DefaultToSPDX switches the format to SPDX when attesting or signing was
// requested but no explicit format was chosen. Call it from PreRun, where
// the flag change state is known.
//
// The SPDX it picks is 3.0.1. Asking for "spdx" still writes 2.3, for
// everyone who has that in a script; it is only the choice made on the
// caller's behalf that moves.
func (fo *formatOptions) DefaultToSPDX(cmd *cobra.Command) {
	flag := fo.Config().LongFlag("format")
	if (fo.Attest || fo.Sign) &&
		!cmd.Flags().Changed(flag) && !cmd.PersistentFlags().Changed(flag) {
		fo.Format = formatSPDX3
	}
}

// ProtobomFormat translates the format selection to a protobom serializer
// format. The boolean reports whether the selection is an SBOM format at
// all — the tree view returns false.
func (fo *formatOptions) ProtobomFormat() (formats.Format, bool) {
	switch fo.Format {
	case formatSPDX:
		return formats.SPDX23JSON, true
	case formatSPDX3:
		return formats.SPDX3JSON, true
	case formatCDX, formatCDXS:
		return formats.CDX17JSON, true
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

// artifactOptions is the reusable options set controlling the scan for
// artifacts that carry their own dependency data (Go executables, for
// now) inside a subject such as a container image: the master switch and
// the per-decomposer switches.
type artifactOptions struct {
	config *command.OptionsSetConfig

	// NoArtifacts turns the artifact scan off entirely.
	NoArtifacts bool

	// SkipArtifacts names the artifact decomposers not to run, by name.
	SkipArtifacts []string

	// SkipPaths lists paths not to scan, as gitignore-style patterns
	// relative to the root.
	SkipPaths []string

	// ScanSystemDirs also scans the system directories a whole-system
	// scan skips by default.
	ScanSystemDirs bool
}

var _ command.OptionsSet = (*artifactOptions)(nil)

// Config returns the flag configuration of the artifact options.
func (ao *artifactOptions) Config() *command.OptionsSetConfig {
	if ao.config == nil {
		ao.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"no-artifacts": {
					Long: "no-artifacts",
					Help: "do not scan the subject for artifacts carrying dependency data (e.g. Go binaries)",
				},
				"skip-artifact": {
					Long: "skip-artifact",
					Help: "artifact decomposers not to run, by name (e.g. gobinary)",
				},
				"skip-path": {
					Long: "skip-path",
					Help: "paths not to scan for artifacts, as gitignore-style patterns relative to the root (e.g. /opt/vendor/, *.so)",
				},
				"scan-system-dirs": {
					Long: "scan-system-dirs",
					Help: "also scan the system directories skipped by default (/usr/bin, /usr/lib, /etc, ...)",
				},
			},
		}
	}
	return ao.config
}

// AddFlags adds the artifact flags to a command that scans a whole system
// as part of a bigger job: the master switch, the default-skip override
// and the flags every scan has.
func (ao *artifactOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&ao.NoArtifacts, ao.Config().LongFlag("no-artifacts"), false, ao.Config().HelpText("no-artifacts"),
	)
	cmd.PersistentFlags().BoolVar(
		&ao.ScanSystemDirs, ao.Config().LongFlag("scan-system-dirs"), false, ao.Config().HelpText("scan-system-dirs"),
	)
	ao.AddScanFlags(cmd)
}

// AddScanFlags adds the flags every artifact scan has, the per-decomposer
// and per-path skips, for commands where the scan itself is the point: a
// master switch would be meaningless there, and no directory is skipped
// by default.
func (ao *artifactOptions) AddScanFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(
		&ao.SkipArtifacts, ao.Config().LongFlag("skip-artifact"), nil, ao.Config().HelpText("skip-artifact"),
	)
	cmd.PersistentFlags().StringSliceVar(
		&ao.SkipPaths, ao.Config().LongFlag("skip-path"), nil, ao.Config().HelpText("skip-path"),
	)
}

// Validate checks the artifact options.
func (ao *artifactOptions) Validate() error { return nil }

// Decomposers returns the per-decomposer switches the flags amount to: an
// off entry for each skipped decomposer, nothing for the rest.
func (ao *artifactOptions) Decomposers() map[string]bool {
	if len(ao.SkipArtifacts) == 0 {
		return nil
	}
	switches := make(map[string]bool, len(ao.SkipArtifacts))
	for _, name := range ao.SkipArtifacts {
		switches[name] = false
	}
	return switches
}

// The values of the --networking flag.
const (
	networkEssential = "essential"
	networkFull      = "full"
	networkDisabled  = "disabled"
)

var networkLevels = []string{networkEssential, networkFull, networkDisabled}

// validateNetworking checks the value of a --networking flag.
func validateNetworking(name string) error {
	if !slices.Contains(networkLevels, name) {
		return fmt.Errorf("invalid networking level %q (must be essential, full, or disabled)", name)
	}
	return nil
}

// stitchOptions is the reusable options set that adds supplemental bills
// of materials to a command's output: documents describing components the
// extraction finds but cannot open, such as a binary without embedded
// dependency data, get stitched under those components.
type stitchOptions struct {
	config *command.OptionsSetConfig

	// AddSBOMs lists supplemental SBOMs to stitch in: files, or
	// directories of them.
	AddSBOMs []string

	stitcher *stitch.Stitcher
}

var _ command.OptionsSet = (*stitchOptions)(nil)

// Config returns the flag configuration of the stitch options.
func (so *stitchOptions) Config() *command.OptionsSetConfig {
	if so.config == nil {
		so.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"add-sbom": {
					Long: "add-sbom",
					Help: "supplemental SBOM (file or directory of files) whose data is stitched under the components it describes when they are found",
				},
			},
		}
	}
	return so.config
}

// AddFlags adds the stitch flags to a command.
func (so *stitchOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(
		&so.AddSBOMs, so.Config().LongFlag("add-sbom"), nil, so.Config().HelpText("add-sbom"),
	)
}

// Validate loads the supplements, so a bad path fails before any work.
func (so *stitchOptions) Validate() error {
	if len(so.AddSBOMs) == 0 || so.stitcher != nil {
		return nil
	}
	catalog := stitch.NewCatalog()
	if err := catalog.Load(so.AddSBOMs...); err != nil {
		return fmt.Errorf("loading supplemental SBOMs: %w", err)
	}
	for _, p := range catalog.Unparsed() {
		logrus.Infof("skipped %s: not a bill of materials", p)
	}
	so.stitcher = stitch.New(catalog)
	return nil
}

// Stitch enriches a node list with the supplements, if any were given.
func (so *stitchOptions) Stitch(nl *protosbom.NodeList) error {
	if so.stitcher == nil {
		return nil
	}
	report, err := so.stitcher.Stitch(nl)
	if err != nil {
		return err
	}
	for _, s := range report.Stitched {
		logrus.Debugf("stitched %s from %s", s.Entry.Node.GetName(), s.Entry.Supplement.Source)
	}
	return nil
}

// ReportUnused warns about the supplements that described nothing the
// command found. Call it once, after every list has been stitched.
func (so *stitchOptions) ReportUnused() {
	if so.stitcher == nil {
		return
	}
	for _, e := range so.stitcher.Catalog.Unused() {
		name := e.Node.GetName()
		if v := e.Node.GetVersion(); v != "" {
			name += "@" + v
		}
		logrus.Warnf("supplemental SBOM %s describes %s, which was not found", e.Supplement.Source, name)
	}
}

// networkLevel maps the value of a --networking flag to the API level.
// Anything but full or disabled is the essential default.
func networkLevel(name string) api.NetworkLevel {
	switch name {
	case networkFull:
		return api.NetworkFull
	case networkDisabled:
		return api.NetworkDisabled
	default:
		return api.NetworkEssential
	}
}

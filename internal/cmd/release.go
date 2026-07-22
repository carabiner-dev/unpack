// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command/output"
	"github.com/carabiner-dev/protograph"
	"github.com/carabiner-dev/signer"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/unpack/release"
)

// releaseOptions assembles the reusable option sets shared with the other
// subcommands plus the release-specific bits.
type releaseOptions struct {
	formatOptions
	Output output.Options

	// Reference points at the release to unpack, parsed from the positional
	// argument.
	Reference *release.Reference
}

// Validate checks the options of all the embedded sets.
func (ro *releaseOptions) Validate() error {
	errs := []error{}
	if ro.Reference == nil {
		errs = append(errs, errors.New("no release reference specified"))
	}
	errs = append(errs,
		ro.formatOptions.Validate(),
		ro.Output.Validate(),
	)
	return errors.Join(errs...)
}

// AddFlags adds the flags of all the embedded option sets to the command.
func (ro *releaseOptions) AddFlags(cmd *cobra.Command) {
	ro.formatOptions.AddFlags(cmd)
	ro.Output.AddFlags(cmd)
}

func addRelease(parent *cobra.Command) {
	opts := &releaseOptions{}

	releaseCmd := &cobra.Command{
		Short: "extract the artifact data of a software release",
		Long: fmt.Sprintf(`%s release: software release artifact extractor

Unpack release reads a release published on a supported forge (GitHub and
GitLab, including self-managed instances) and extracts its data: the
release itself at the top of the tree, pinned to the commit it was built
from, with one node per published artifact carrying its name, download
location and digests.

Releases are referenced by a string locating the forge type, the instance
host, the repository and, optionally, the release tag. Three forms are
understood:

  github:org/repo@v1.0.0                       Shorthand, public instance
  gitlab:group/subgroup/project@v1.0.0         GitLab paths may nest groups
  github:ghe.example.com/org/repo@v1.0.0       Shorthand, self-managed host
  github+https://github.com/org/repo@v1.0.0    Canonical form
  https://github.com/org/repo/releases/tag/v1  A pasted release page URL

Omitting the @tag points the reference at the repository's latest release.
Public releases need no credentials; a token in GITHUB_TOKEN or
GITLAB_TOKEN is used when present (and needed for private repositories).

By default, the release data is displayed as an ASCII tree in the terminal
but it can be exported as an SPDX or CycloneDX SBOM, wrapped in an in-toto
attestation, or signed into a sigstore bundle.

Usage patterns:
  %[1]s release github:org/repo@v1.0.0            Show the release tree
  %[1]s release github:org/repo                   Same, at the latest release
  %[1]s release -f spdx github:org/repo@v1.0.0    Output an SPDX SBOM
  %[1]s release --attest github:org/repo@v1.0.0   Wrap the SBOM in an attestation
  %[1]s release --sign -o a.json github:org/repo@v1.0.0  Sign it into a bundle

`, appname),
		Use:               "release [flags] REFERENCE",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		Args:              cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			ref, err := release.ParseReference(args[0])
			if err != nil {
				return err
			}
			opts.Reference = ref
			opts.DefaultToSPDX(cmd)
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			unpacker := release.NewUnpacker()
			lists, err := unpacker.Extract(cmd.Context(), opts.Reference)
			if err != nil {
				return fmt.Errorf("extracting release: %w", err)
			}
			if len(lists) == 0 || lists[0] == nil {
				return errors.New("no release data found")
			}
			nodelist := lists[0]

			format, isSbom := opts.ProtobomFormat()
			if !isSbom {
				pg := protograph.New()
				return pg.GraphNodeList(nodelist)
			}

			w, err := opts.Output.GetWriter()
			if err != nil {
				return err
			}
			wr := asWriteCloser(w)
			defer wr.Close() //nolint:errcheck // best-effort close; render errors surface below

			switch {
			case opts.Sign:
				err = nodeListToSignedAttestation(signer.NewSigner(), wr, format, nodelist)
			case opts.Attest:
				err = nodeListToAttestation(wr, format, nodelist)
			default:
				err = nodeListToSbom(wr, format, nodelist)
			}
			if err != nil {
				return fmt.Errorf("rendering SBOM: %w", err)
			}
			return nil
		},
	}

	opts.AddFlags(releaseCmd)
	parent.AddCommand(releaseCmd)
}

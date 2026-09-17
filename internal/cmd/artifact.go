// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/carabiner-dev/command/output"
	"github.com/carabiner-dev/protograph"
	"github.com/carabiner-dev/signer"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spf13/cobra"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact"
)

// artifactCmdOptions assembles the reusable option sets shared with the
// other subcommands plus the artifact-specific bits.
type artifactCmdOptions struct {
	formatOptions
	artifactOptions
	Output output.Options

	// Path is the artifact to unpack, or a directory to scan for
	// artifacts, taken from the positional argument.
	Path string

	// Networking is the network access level for the artifact decomposers.
	Networking string
}

// Validate checks the options of all the embedded sets.
func (ao *artifactCmdOptions) Validate() error {
	errs := []error{}
	if ao.Path == "" {
		errs = append(errs, errors.New("no artifact path specified"))
	}
	errs = append(errs,
		validateNetworking(ao.Networking),
		ao.formatOptions.Validate(),
		ao.artifactOptions.Validate(),
		ao.Output.Validate(),
	)
	return errors.Join(errs...)
}

// AddFlags adds the flags of all the embedded option sets to the command.
// Of the artifact set only the per-decomposer switch applies: turning the
// scan off wholesale makes no sense on a command that is the scan.
func (ao *artifactCmdOptions) AddFlags(cmd *cobra.Command) {
	ao.formatOptions.AddFlags(cmd)
	ao.AddSkipFlag(cmd)
	ao.Output.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&ao.Networking, "networking", networkEssential,
		"network access level: essential (default), full, or disabled",
	)
}

// subject wraps the path as the artifact subject to unpack: the file
// itself, or a filesystem to scan when the path is a directory.
func (ao *artifactCmdOptions) subject() (api.DecomposableSubject, error) {
	info, err := os.Stat(ao.Path)
	if err != nil {
		return nil, fmt.Errorf("reading artifact path: %w", err)
	}
	if info.IsDir() {
		return &artifact.Filesystem{FS: os.DirFS(ao.Path)}, nil
	}
	return &artifact.File{Path: ao.Path}, nil
}

func addArtifact(parent *cobra.Command) {
	opts := &artifactCmdOptions{}

	artifactCmd := &cobra.Command{
		Short: "extract the dependency data embedded in a built artifact",
		Long: fmt.Sprintf(`%s artifact: built artifact dependency extractor

Unpack artifact reads the dependency data that build tools embed in the
artifacts they produce. A Go executable, for example, carries the exact set
of modules linked into it, with versions and checksums, and the Go release
that built it. The result is the artifact file at the top of the tree,
identified by its digest, with the package it was generated from below it
and that package's dependencies as descendants.

The path may be a single file or a directory. A directory is scanned for
every artifact of a kind %[1]s understands; files it does not recognize are
skipped. Every artifact decomposer runs here, whatever its defaults are when
scanning inside a container image. Use --skip-artifact to leave one out.

By default, dependencies are displayed as an ASCII tree in the terminal but
the data can be exported as an SPDX or CycloneDX SBOM, wrapped in an in-toto
attestation, or signed into a sigstore bundle.

Usage patterns:
  %[1]s artifact ./bin/tool                  Show the dependency tree of a binary
  %[1]s artifact ./dist                      Scan a directory for artifacts
  %[1]s artifact -f spdx ./bin/tool          Output an SPDX SBOM
  %[1]s artifact --attest ./bin/tool         Wrap the SBOM in an attestation
  %[1]s artifact --sign -o a.json ./bin/tool Sign it into a sigstore bundle

`, appname),
		Use:               "artifact [flags] PATH",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		Args:              cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts.Path = args[0]
			opts.DefaultToSPDX(cmd)
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			subject, err := opts.subject()
			if err != nil {
				return err
			}

			unpacker := artifact.NewUnpacker()
			unpacker.Options.Decomposers = opts.Decomposers()
			unpacker.Options.Networking = networkLevel(opts.Networking)

			lists, err := unpacker.Extract(cmd.Context(), subject)
			if err != nil {
				return fmt.Errorf("extracting artifact data: %w", err)
			}
			if len(lists) == 0 {
				return fmt.Errorf("no dependency data found in %s: not a recognized artifact", opts.Path)
			}

			// A directory may hold several artifacts. They share one
			// document, each as a root of its own.
			nodelist := sbom.NewNodeList()
			for _, nl := range lists {
				nodelist.Add(nl)
			}

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

	opts.AddFlags(artifactCmd)
	parent.AddCommand(artifactCmd)
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/command/output"
	"github.com/carabiner-dev/protograph"
	"github.com/carabiner-dev/signer"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/unpack/image"
)

// imageOptions assembles the reusable option sets shared with extract plus
// the image-specific bits.
type imageOptions struct {
	formatOptions
	filesOptions
	Output output.Options

	// Reference is the OCI reference of the image to unpack, taken from
	// the positional argument.
	Reference string
}

// Validate checks the options of all the embedded sets.
func (io_ *imageOptions) Validate() error {
	errs := []error{}
	if io_.Reference == "" {
		errs = append(errs, errors.New("no image reference specified"))
	}
	errs = append(errs,
		io_.formatOptions.Validate(),
		io_.filesOptions.Validate(),
		io_.Output.Validate(),
	)
	return errors.Join(errs...)
}

// AddFlags adds the flags of all the embedded option sets to the command.
func (io_ *imageOptions) AddFlags(cmd *cobra.Command) {
	io_.formatOptions.AddFlags(cmd)
	io_.filesOptions.AddFlags(cmd)
	io_.Output.AddFlags(cmd)
}

func addImage(parent *cobra.Command) {
	opts := &imageOptions{}

	imageCmd := &cobra.Command{
		Short: "extract the dependency tree of a container image",
		Long: fmt.Sprintf(`%s image: container image dependency extractor

Unpack image takes the OCI reference of a container image, downloads it,
squashes its layers into the filesystem a running container would see, and
extracts the operating system packages installed in it (apk, dpkg and rpm
databases, including distroless images).

For a single-arch image the result is the image at the top with its packages
as descendants. For a multi-arch image, the index sits at the top with one
node per platform image, each carrying its own packages.

By default, dependencies are displayed as an ASCII tree in the terminal but
the data can be exported as an SPDX or CycloneDX SBOM, wrapped in an in-toto
attestation, or signed into a sigstore bundle.

Usage patterns:
  %[1]s image alpine:3.21                  Show the package tree of an image
  %[1]s image -f spdx alpine:3.21          Output an SPDX SBOM
  %[1]s image --files -f spdx alpine:3.21  Include the package file lists
  %[1]s image --attest alpine:3.21         Wrap the SBOM in an attestation
  %[1]s image --sign -o a.json alpine:3.21 Sign it into a sigstore bundle

`, appname),
		Use:               "image [flags] REFERENCE",
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		Args:              cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts.Reference = args[0]
			opts.DefaultToSPDX(cmd)
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			unpacker := image.NewUnpacker()
			unpacker.Options.IncludeFiles = opts.Files

			lists, err := unpacker.Extract(cmd.Context(), &image.Reference{Ref: opts.Reference})
			if err != nil {
				return fmt.Errorf("extracting image: %w", err)
			}
			if len(lists) == 0 || lists[0] == nil {
				return errors.New("no dependency data found in image")
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

	opts.AddFlags(imageCmd)
	parent.AddCommand(imageCmd)
}

// asWriteCloser adapts a writer to the WriteCloser the renderers expect,
// without closing writers we don't own (stdout).
func asWriteCloser(w io.Writer) io.WriteCloser {
	if w == io.Writer(os.Stdout) {
		return nopWriteCloser{w}
	}
	if wc, ok := w.(io.WriteCloser); ok {
		return wc
	}
	return nopWriteCloser{w}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

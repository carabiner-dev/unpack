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
	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"
)

const appname = "unpack"

var opts = rootOptions{}

var rootCmd = &cobra.Command{
	Short: fmt.Sprintf("%s: dependency data extractor", appname),
	Long: fmt.Sprintf(`%s: dependency data extractor

Unpack takes a source like a source code directory, an artifact, etc. And
it applies a decomposer to read its dependency data.

`, appname),
	Use:               fmt.Sprintf("%s [flags] source", appname),
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

		doc := &sbom.Document{
			Metadata: &sbom.Metadata{
				Id:   uuid.NewString(),
				Date: timestamppb.Now(),
				Tools: []*sbom.Tool{
					{
						Name:    appname,
						Version: version.GetVersionInfo().GitVersion,
						Vendor:  "Carabiner Systems, Inc",
					},
				},
			},
			NodeList: nodelist,
		}

		w := writer.New(writer.WithFormat(format))
		return w.WriteStream(doc, os.Stdout)
	},
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

type rootOptions struct {
	Path   string
	Format string
}

var validFormats = []string{"spdx", "cyclonedx", "cdx", "tree"}

// Validates the options in context with arguments
func (ro *rootOptions) Validate() error {
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
func (ro *rootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&ro.Path, "path", "p", "", "path to the artifact to unpack",
	)
	cmd.PersistentFlags().StringVarP(
		&ro.Format, "format", "f", "tree", fmt.Sprintf("format for the output %+v", validFormats),
	)
}

// Execute builds the command
func Execute() {
	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level", "info", fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)
	// rootCmd.AddCommand(version.WithFont("doom"))
	opts.AddFlags(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

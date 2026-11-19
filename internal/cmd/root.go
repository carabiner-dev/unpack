// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/chainguard-dev/clog"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"
)

const appname = "unpack"

func rootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Short:             fmt.Sprintf("%s: your handy dependency extractor", appname),
		Long:              fmt.Sprintf("%s: your handy dependency extractor", appname),
		Use:               appname,
		SilenceUsage:      false,
		PersistentPreRunE: initLogging,
		Example: fmt.Sprintf(`
Extract the dependency data of a code base im a tree: 

%s extract /path/to/code

Same but output in an SPDX SBOM:

%s extract --format=spdx /path/to/code 


Extract the dependency data from an SBOM:

%s sbom /path/to/sbom.spdx.json

Same but output the SBOM data in another format:

%s sbom --format=cyclonedx /path/to/sbom.spdx.json

Extract the system packages installed in a container image:

%s image alpine:3.21

Extract the artifacts published in a GitHub release:

%s release github:carabiner-dev/unpack@v0.2.0

`, appname, appname, appname, appname, appname, appname),
	}

	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level", "info", fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)

	return rootCmd
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

// initLogging sets up logging for the command about to run, from
// --log-level.
//
// The library logs through the logger in the context it is called with and
// stays silent without one, so the command's context is given one writing
// to standard error. The parts of the program that still log through
// logrus are configured as before.
func initLogging(cmd *cobra.Command, _ []string) error {
	if err := log.SetupGlobalLogger(commandLineOpts.logLevel); err != nil {
		return err
	}

	level, err := slogLevel(commandLineOpts.logLevel)
	if err != nil {
		return err
	}
	logger := clog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level}))

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cmd.SetContext(clog.WithLogger(ctx, logger))
	return nil
}

// slogLevel reads a --log-level value, which names a logrus level, as the
// slog level that shows the same messages. slog has four levels to
// logrus's seven: trace shows what debug does, and fatal and panic what
// error does.
func slogLevel(name string) (slog.Level, error) {
	level, err := logrus.ParseLevel(name)
	if err != nil {
		return 0, fmt.Errorf("reading the log level: %w", err)
	}
	switch level {
	case logrus.TraceLevel, logrus.DebugLevel:
		return slog.LevelDebug, nil
	case logrus.InfoLevel:
		return slog.LevelInfo, nil
	case logrus.WarnLevel:
		return slog.LevelWarn, nil
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		return slog.LevelError, nil
	}
	return slog.LevelInfo, nil
}

// Execute builds the command
func Execute() {
	rootCmd := rootCommand()

	addExtract(rootCmd)
	addImage(rootCmd)
	addArtifact(rootCmd)
	addSBOM(rootCmd)
	addLs(rootCmd)
	addRelease(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

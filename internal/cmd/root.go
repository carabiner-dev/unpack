// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"

	"github.com/carabiner-dev/unpack/internal/logging"
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
		"log-level", "info", "the logging verbosity, one of "+strings.Join(logLevels, ", "),
	)

	return rootCmd
}

type commandLineOptions struct {
	logLevel string

	// logger is the program's logger, set from --log-level before a
	// command runs. It is also the one in the command's context, which
	// is how the library finds it; the commands' own code reads it here.
	logger *clog.Logger
}

// cliLog returns the program's logger, and a silent one before any
// command has set it up, as in a test calling the commands' code directly.
func cliLog() *clog.Logger {
	if commandLineOpts.logger == nil {
		return logging.Silent()
	}
	return commandLineOpts.logger
}

// logLevels are the values --log-level takes, most verbose last. They are
// the names the flag has always taken; several show the same messages,
// as the logger has four levels (see slogLevel).
var logLevels = []string{"panic", "fatal", "error", "warn", "warning", "info", "debug", "trace"}

var commandLineOpts = commandLineOptions{}

// initLogging sets up logging for the command about to run, from
// --log-level.
//
// The library logs through the logger in the context it is called with and
// stays silent without one, so the command's context is given one writing
// to standard error. The commands' own messages go to the same logger.
func initLogging(cmd *cobra.Command, _ []string) error {
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
	commandLineOpts.logger = logger
	return nil
}

// slogLevel reads a --log-level value as the level that shows its
// messages. The flag takes seven names and the logger has four levels:
// trace shows what debug does, and fatal and panic what error does.
func slogLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "trace", "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "fatal", "panic":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q, it is one of %s", name, strings.Join(logLevels, ", "))
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

	// cobra has printed the error by now.
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

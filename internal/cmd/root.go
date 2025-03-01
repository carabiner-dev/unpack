// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

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
		Example:           fmt.Sprintf(``),
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

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

// Execute builds the command
func Execute() {
	rootCmd := rootCommand()

	addExtract(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

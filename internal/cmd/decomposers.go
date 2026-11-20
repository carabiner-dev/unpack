// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/unpack/dependencies"
)

// decomposerOptions are the flags that choose which decomposers read a
// codebase, by the name of their language.
type decomposerOptions struct {
	Enable  []string
	Disable []string
}

// AddDecomposerFlags adds the flags to a command.
func (do *decomposerOptions) AddDecomposerFlags(cmd *cobra.Command) {
	names := dependencies.NewUnpacker()
	cmd.PersistentFlags().StringSliceVar(
		&do.Enable, "enable", nil,
		fmt.Sprintf(
			"decomposers to run that do not run by default, by name; repeatable or comma separated (known decomposers: %s)",
			strings.Join(names.DecomposerNames(), ", "),
		),
	)
	cmd.PersistentFlags().StringSliceVar(
		&do.Disable, "disable", nil,
		fmt.Sprintf(
			"decomposers to leave out, by name; repeatable or comma separated (run by default: %s)",
			strings.Join(names.DefaultDecomposerNames(), ", "),
		),
	)
}

// ValidateDecomposers checks the flags do not contradict each other. Whether the
// names are known is checked against the unpacker, in ApplyDecomposers: what it
// knows depends on the other flags.
func (do *decomposerOptions) ValidateDecomposers() error {
	var errs []error
	for _, name := range do.Enable {
		if slices.Contains(do.Disable, name) {
			errs = append(errs, fmt.Errorf("decomposer %q is both enabled and disabled", name))
		}
	}
	return errors.Join(errs...)
}

// ApplyDecomposers switches the decomposers of an unpacker as the flags
// say. Call it after the decomposers other flags bring in are registered.
func (do *decomposerOptions) ApplyDecomposers(unpacker *dependencies.Unpacker) error {
	if len(do.Enable) == 0 && len(do.Disable) == 0 {
		return nil
	}
	known := unpacker.DecomposerNames()

	var errs []error
	switches := map[string]bool{}
	for _, name := range do.Enable {
		switches[name] = true
	}
	for _, name := range do.Disable {
		switches[name] = false
	}
	for _, name := range slices.Sorted(maps.Keys(switches)) {
		switch {
		case slices.Contains(known, name):
		case name == sbtName:
			// It reads a file only its own flag can name.
			errs = append(errs, errors.New("the sbt decomposer is enabled by giving it a snapshot with --sbt-snapshot"))
		default:
			errs = append(errs, fmt.Errorf("unknown decomposer %q, the known ones are %s", name, strings.Join(known, ", ")))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if unpacker.Options.Decomposers == nil {
		unpacker.Options.Decomposers = map[string]bool{}
	}
	for name, on := range switches {
		unpacker.Options.Decomposers[name] = on
	}
	return nil
}

// sbtName is the name the sbt decomposer is registered under.
const sbtName = "sbt"

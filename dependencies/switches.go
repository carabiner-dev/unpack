// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/cmake"
)

// This file is how a caller chooses which decomposers an unpacker runs.
//
// Decomposers go by the name of their language, the one codebase IDs
// carry (golang:., npm:web). Most run unless switched off. Some only run
// when switched on: those whose reading is an approximation, or costly,
// which nobody should get without asking. Options.Decomposers switches
// either kind by name.

// optionalDecomposers are the decomposers the unpacker knows and does not
// run unless they are switched on, each with how to make one.
var optionalDecomposers = map[string]func() api.Decomposer{
	// CMake files say what a project may depend on, and not what a
	// build of it has.
	"cmake": func() api.Decomposer { return cmake.New() },
}

// ErrUnknownDecomposer is returned when a decomposer is switched on or
// off by a name the unpacker does not know.
var ErrUnknownDecomposer = fmt.Errorf("unknown decomposer")

// DecomposerNames returns the names of the decomposers the unpacker
// knows, sorted: the ones it runs by default, the ones it runs when
// switched on, and any the caller registered.
func (unpacker *Unpacker) DecomposerNames() []string {
	names := slices.Collect(maps.Keys(unpacker.decomposers))
	for name := range unpacker.available {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// DefaultDecomposerNames returns the names of the decomposers that run
// when nothing says otherwise, sorted.
func (unpacker *Unpacker) DefaultDecomposerNames() []string {
	names := slices.Collect(maps.Keys(unpacker.decomposers))
	slices.Sort(names)
	return names
}

// activeDecomposers returns the decomposers to run: the registered ones,
// less those Options.Decomposers switches off, plus the optional ones it
// switches on. A name the unpacker does not know is an error, whichever
// way it is switched: a misspelt name must not pass for a decomposer that
// found nothing.
func (unpacker *Unpacker) activeDecomposers() (map[string]api.Decomposer, error) {
	active := maps.Clone(unpacker.decomposers)

	unknown := []string{}
	for _, name := range slices.Sorted(maps.Keys(unpacker.Options.Decomposers)) {
		on := unpacker.Options.Decomposers[name]
		_, registered := unpacker.decomposers[name]
		construct, optional := unpacker.available[name]

		switch {
		case !registered && !optional:
			unknown = append(unknown, name)
		case !on:
			delete(active, name)
		case !registered:
			// Made once and kept: a decomposer is found again by
			// identity between scanning and extracting.
			d := construct()
			unpacker.decomposers[name] = d
			active[name] = d
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf(
			"%w %s, the known ones are %s",
			ErrUnknownDecomposer, strings.Join(unknown, ", "), strings.Join(unpacker.DecomposerNames(), ", "),
		)
	}
	return active, nil
}

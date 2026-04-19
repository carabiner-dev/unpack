// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import "fmt"

// NetworkLevel controls how much network access the decomposers are allowed to use.
type NetworkLevel int

const (
	// NetworkEssential is the default (zero value). Enables network calls
	// that are essential for building the dependency tree plus lightweight
	// metadata requests (e.g., deps.dev, checksum files, crates.io API).
	NetworkEssential NetworkLevel = iota

	// NetworkFull enables all network calls including downloading full
	// artifacts for hash computation and zip archives for license
	// classification. Prioritizes data completeness over bandwidth.
	NetworkFull

	// NetworkDisabled disables all network calls. Only local data is used.
	// Some decomposers may produce incomplete results or fail entirely.
	NetworkDisabled NetworkLevel = -1
)

// DecomposerOptions is the options set that goes into an Extract() run in
// a decomposer. They are meant to be ephimeral, for the invocation only, and
// derived from the Unpacker configuration whe invoked from there.
type DecomposerOptions struct {
	WorkDir string

	// Version is the version to use on the resulting root nodes after decomposing
	Version string

	// CommitHash captures the hash of the last commit when running in a repository
	CommitHash string

	// Networking controls how much network access decomposers are allowed.
	// Defaults to NetworkEssential.
	Networking NetworkLevel

	driverOptions map[string]any
}

func (so *DecomposerOptions) SetDriverOptions(dec Decomposer, opts any) {
	if dec == nil {
		return
	}
	if so.driverOptions == nil {
		so.driverOptions = map[string]any{}
	}
	so.driverOptions[fmt.Sprintf("%T", dec)] = opts
}

func (so *DecomposerOptions) GetDriverOptions(dec Decomposer) any {
	if so.driverOptions == nil {
		return nil
	}
	if opts, ok := so.driverOptions[fmt.Sprintf("%T", dec)]; ok {
		return opts
	}
	return nil
}

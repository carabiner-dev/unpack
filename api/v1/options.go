// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import "fmt"

// DecomposerOptions is the options set that goes into an Extract() run in
// a decomposer. They are meant to be ephimeral, for the invocation only, and
// derived from the Unpacker configuration whe invoked from there.
type DecomposerOptions struct {
	WorkDir string

	// Version is the version to use on the resulting root nodes after decomposing
	Version string

	// CommitHash captures the hash of the last commit when running in a repository
	CommitHash string

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

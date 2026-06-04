// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/protobom/protobom/pkg/sbom"
)

// Unpacker is the entry point for dependency extraction. An unpacker knows
// about one kind of subject matter (codebases, SBOMs, artifacts, ...) and uses
// Decomposers to crack open the different flavors of that subject.
//
// While processing its subject, an unpacker may discover child subjects that
// contain further dependency data (e.g. a filesystem that contains codebases,
// or a container image that contains an OS package database). It dispatches
// those child subjects to the unpacker that handles them by looking them up in
// the registry (see UnpackerFor), so extraction composes recursively.
type Unpacker interface {
	// Extract reads dependency data from the given subject and returns the
	// resulting nodelists.
	Extract(context.Context, DecomposableSubject) ([]*sbom.NodeList, error)

	// RegisterDecomposer adds a decomposer to the unpacker.
	RegisterDecomposer(Decomposer)

	// UnregisterDecomposer removes a decomposer from the unpacker.
	UnregisterDecomposer(Decomposer)
}

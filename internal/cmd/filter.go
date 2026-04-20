// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/protobom/protobom/pkg/sbom"
)

// filterNodeListByEdgeType removes nodes from the NodeList that are only
// reachable via excluded edge types. A node is removed only if ALL edges
// pointing to it are of excluded types — if any included edge also
// reaches the node, it is kept.
func filterNodeListByEdgeType(nl *sbom.NodeList, opts *sbomOptions) {
	// Build the set of excluded edge types based on options
	excluded := make(map[sbom.Edge_Type]struct{})
	if !opts.IncludeDev {
		excluded[sbom.Edge_devDependency] = struct{}{}
	}
	if !opts.IncludeBuild {
		excluded[sbom.Edge_buildDependency] = struct{}{}
	}
	if !opts.IncludeOptional {
		excluded[sbom.Edge_optionalDependency] = struct{}{}
	}

	if len(excluded) == 0 {
		return // nothing to filter
	}

	// Track which node IDs are targets of excluded-only edges vs included edges
	includedTargets := make(map[string]struct{})
	excludedTargets := make(map[string]struct{})

	for _, edge := range nl.GetEdges() {
		_, isExcluded := excluded[edge.GetType()]
		for _, toID := range edge.GetTo() {
			if isExcluded {
				excludedTargets[toID] = struct{}{}
			} else {
				includedTargets[toID] = struct{}{}
			}
		}
	}

	// Collect IDs to remove: nodes that appear only in excluded edges
	var toRemove []string
	for id := range excludedTargets {
		if _, kept := includedTargets[id]; !kept {
			toRemove = append(toRemove, id)
		}
	}

	if len(toRemove) > 0 {
		nl.RemoveNodes(toRemove)
	}
}

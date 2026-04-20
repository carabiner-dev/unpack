// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

// buildTestNodeList creates a NodeList with a root and four dependencies,
// each connected via a different edge type:
//
//	root --dependsOn--> prod-dep
//	root --devDependency--> dev-dep
//	root --buildDependency--> build-dep
//	root --optionalDependency--> optional-dep
//	root --dependsOn--> shared-dep
//	root --devDependency--> shared-dep  (shared-dep reached by both)
func buildTestNodeList() *sbom.NodeList {
	nl := sbom.NewNodeList()

	root := &sbom.Node{Id: "root", Name: "my-app", Version: "1.0.0"}
	prodDep := &sbom.Node{Id: "prod", Name: "prod-dep", Version: "1.0"}
	devDep := &sbom.Node{Id: "dev", Name: "dev-dep", Version: "1.0"}
	buildDep := &sbom.Node{Id: "build", Name: "build-dep", Version: "1.0"}
	optDep := &sbom.Node{Id: "opt", Name: "optional-dep", Version: "1.0"}
	sharedDep := &sbom.Node{Id: "shared", Name: "shared-dep", Version: "1.0"}

	nl.AddRootNode(root)

	//nolint:errcheck,gosec // test helper — these calls always succeed with valid node IDs
	nl.RelateNodeAtID(prodDep, "root", sbom.Edge_dependsOn)
	//nolint:errcheck,gosec
	nl.RelateNodeAtID(devDep, "root", sbom.Edge_devDependency)
	//nolint:errcheck,gosec
	nl.RelateNodeAtID(buildDep, "root", sbom.Edge_buildDependency)
	//nolint:errcheck,gosec
	nl.RelateNodeAtID(optDep, "root", sbom.Edge_optionalDependency)
	//nolint:errcheck,gosec
	nl.RelateNodeAtID(sharedDep, "root", sbom.Edge_dependsOn)
	nl.AddEdge(&sbom.Edge{
		Type: sbom.Edge_devDependency,
		From: "root",
		To:   []string{"shared"},
	})

	return nl
}

func nodeNames(nl *sbom.NodeList) map[string]bool {
	names := make(map[string]bool)
	for _, n := range nl.GetNodes() {
		names[n.GetName()] = true
	}
	return names
}

func TestFilterAllIncluded(t *testing.T) {
	t.Parallel()
	nl := buildTestNodeList()
	opts := &sbomOptions{IncludeDev: true, IncludeBuild: true, IncludeOptional: true}

	filterNodeListByEdgeType(nl, opts)

	names := nodeNames(nl)
	require.Len(t, names, 6) // root + 5 deps
	require.True(t, names["prod-dep"])
	require.True(t, names["dev-dep"])
	require.True(t, names["build-dep"])
	require.True(t, names["optional-dep"])
	require.True(t, names["shared-dep"])
}

func TestFilterExcludeDev(t *testing.T) {
	t.Parallel()
	nl := buildTestNodeList()
	opts := &sbomOptions{IncludeDev: false, IncludeBuild: true, IncludeOptional: true}

	filterNodeListByEdgeType(nl, opts)

	names := nodeNames(nl)
	require.True(t, names["prod-dep"], "prod dep should remain")
	require.False(t, names["dev-dep"], "dev dep should be removed")
	require.True(t, names["build-dep"], "build dep should remain")
	require.True(t, names["optional-dep"], "optional dep should remain")
	require.True(t, names["shared-dep"], "shared dep should remain (also reachable via dependsOn)")
}

func TestFilterExcludeBuild(t *testing.T) {
	t.Parallel()
	nl := buildTestNodeList()
	opts := &sbomOptions{IncludeDev: true, IncludeBuild: false, IncludeOptional: true}

	filterNodeListByEdgeType(nl, opts)

	names := nodeNames(nl)
	require.True(t, names["prod-dep"])
	require.True(t, names["dev-dep"])
	require.False(t, names["build-dep"], "build dep should be removed")
	require.True(t, names["optional-dep"])
	require.True(t, names["shared-dep"])
}

func TestFilterExcludeOptional(t *testing.T) {
	t.Parallel()
	nl := buildTestNodeList()
	opts := &sbomOptions{IncludeDev: true, IncludeBuild: true, IncludeOptional: false}

	filterNodeListByEdgeType(nl, opts)

	names := nodeNames(nl)
	require.True(t, names["prod-dep"])
	require.True(t, names["dev-dep"])
	require.True(t, names["build-dep"])
	require.False(t, names["optional-dep"], "optional dep should be removed")
	require.True(t, names["shared-dep"])
}

func TestFilterExcludeAll(t *testing.T) {
	t.Parallel()
	nl := buildTestNodeList()
	opts := &sbomOptions{IncludeDev: false, IncludeBuild: false, IncludeOptional: false}

	filterNodeListByEdgeType(nl, opts)

	names := nodeNames(nl)
	// Only root, prod-dep, and shared-dep (also reachable via dependsOn) remain
	require.True(t, names["my-app"], "root should remain")
	require.True(t, names["prod-dep"], "prod dep should remain")
	require.True(t, names["shared-dep"], "shared dep should remain (reachable via dependsOn)")
	require.False(t, names["dev-dep"], "dev dep should be removed")
	require.False(t, names["build-dep"], "build dep should be removed")
	require.False(t, names["optional-dep"], "optional dep should be removed")
}

func TestFilterNothingExcluded(t *testing.T) {
	t.Parallel()
	// All flags true means no filtering happens
	nl := buildTestNodeList()
	originalCount := len(nl.GetNodes())
	opts := &sbomOptions{IncludeDev: true, IncludeBuild: true, IncludeOptional: true}

	filterNodeListByEdgeType(nl, opts)

	require.Len(t, nl.GetNodes(), originalCount)
}

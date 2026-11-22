// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// workspace returns a graph with two roots, as a workspace gives: two
// members, one depending on the other and both on a library.
func workspace(t *testing.T) *sbom.NodeList {
	t.Helper()
	nl := sbom.NewNodeList()
	app := &sbom.Node{Id: "app", Name: "app", Version: "1.0", Type: sbom.Node_PACKAGE}
	core := &sbom.Node{Id: "core", Name: "core", Version: "1.0", Type: sbom.Node_PACKAGE}
	lib := &sbom.Node{Id: "lib", Name: "lib", Version: "2.3", Type: sbom.Node_PACKAGE}
	nl.AddRootNode(app)
	nl.AddRootNode(core)
	require.NoError(t, nl.RelateNodeAtID(core, "app", sbom.Edge_dependsOn))
	require.NoError(t, nl.RelateNodeAtID(lib, "app", sbom.Edge_dependsOn))
	require.NoError(t, nl.RelateNodeAtID(lib, "core", sbom.Edge_dependsOn))
	return nl
}

type cycloneDX struct {
	Metadata struct {
		Component *struct {
			Name string `json:"name"`
		} `json:"component"`
		Lifecycles []struct {
			Phase string `json:"phase"`
		} `json:"lifecycles"`
		Tools json.RawMessage `json:"tools"`
	} `json:"metadata"`
	Components []struct {
		Ref  string `json:"bom-ref"`
		Name string `json:"name"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// TestMultiRootCycloneDX checks a graph with several roots is written as
// CycloneDX, which has room for one: with no component of its own, and
// the roots at the top of its components.
func TestMultiRootCycloneDX(t *testing.T) {
	t.Parallel()

	for _, format := range []formats.Format{formats.CDX15JSON, formats.CDX16JSON} {
		buf := &bcloser{Buffer: bytes.Buffer{}}
		require.NoError(t, nodeListToSbom(buf, format, workspace(t),
			withContexts([]api.GenerationContext{api.ContextSource})), format)

		doc := &cycloneDX{}
		require.NoError(t, json.Unmarshal(buf.Buffer.Bytes(), doc), format)
		require.Nil(t, doc.Metadata.Component, "the document names no single subject")

		top := make([]string, 0, len(doc.Components))
		for _, component := range doc.Components {
			top = append(top, component.Name)
		}
		require.ElementsMatch(t, []string{"app", "core"}, top, "the roots are the top-level components")

		edges := map[string][]string{}
		for _, dependency := range doc.Dependencies {
			edges[dependency.Ref] = dependency.DependsOn
		}
		require.ElementsMatch(t, []string{"core", "lib"}, edges["app"])
		require.Equal(t, []string{"lib"}, edges["core"])

		// What the document says of itself is still there.
		require.NotEmpty(t, doc.Metadata.Tools)
		require.Len(t, doc.Metadata.Lifecycles, 1)

		// And it reads back as the graph it was.
		read, err := reader.New().ParseStream(bytes.NewReader(buf.Buffer.Bytes()))
		require.NoError(t, err, format)
		require.Len(t, read.GetNodeList().GetRootElements(), 2)
		require.Len(t, read.GetNodeList().GetNodes(), 3)
	}

	// SPDX describes several packages as it always could.
	buf := &bcloser{Buffer: bytes.Buffer{}}
	require.NoError(t, nodeListToSbom(buf, formats.SPDX23JSON, workspace(t)))
	read, err := reader.New().ParseStream(bytes.NewReader(buf.Buffer.Bytes()))
	require.NoError(t, err)
	require.Len(t, read.GetNodeList().GetRootElements(), 2)
}

// TestSingleRootCycloneDX checks a graph with one root is written as
// ever: the root is the document's component.
func TestSingleRootCycloneDX(t *testing.T) {
	t.Parallel()
	nl := sbom.NewNodeList()
	nl.AddRootNode(&sbom.Node{Id: "app", Name: "app", Version: "1.0", Type: sbom.Node_PACKAGE})
	require.NoError(t, nl.RelateNodeAtID(
		&sbom.Node{Id: "lib", Name: "lib", Version: "2.3", Type: sbom.Node_PACKAGE}, "app", sbom.Edge_dependsOn))

	buf := &bcloser{Buffer: bytes.Buffer{}}
	require.NoError(t, nodeListToSbom(buf, formats.CDX15JSON, nl))
	doc := &cycloneDX{}
	require.NoError(t, json.Unmarshal(buf.Buffer.Bytes(), doc))
	require.NotNil(t, doc.Metadata.Component)
	require.Equal(t, "app", doc.Metadata.Component.Name)
	require.Len(t, doc.Components, 1)
	require.Equal(t, "lib", doc.Components[0].Name)
}

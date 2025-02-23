// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"sigs.k8s.io/release-utils/command"

	"github.com/carabiner-dev/unpack/source"
)

var _ source.Decomposer = (*Decomposer)(nil)

type Decomposer struct{}

// These options not yet wired in
type Options struct {
	IncludeGo bool
}

var defaultOptions = Options{
	IncludeGo: true,
}

func (d *Decomposer) DefaultOptions() any {
	return defaultOptions
}

// Extract calls go to get the data
func (d *Decomposer) Extract(opts source.Options) (*sbom.NodeList, error) {
	var cmd *command.Command
	if opts.WorkDir == "" {
		cmd = command.New("go", "mod", "graph")
	} else {
		cmd = command.NewWithWorkDir(opts.WorkDir, "go", "mod", "graph")
	}

	// Extract the dependency data
	output, err := cmd.RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("error shelling out to go: %w", err)
	}

	trees, err := d.parseGoGraph(output.Output())
	if err != nil {
		return nil, fmt.Errorf("parsing graph: %w", err)
	}

	// Get the main module name from go.mod
	root, err := d.readMainModule(opts)
	if err != nil {
		return nil, fmt.Errorf("reading main module: %w", err)
	}

	// Convert the go package trees to a protobom nodelist
	nl, err := d.convertTrees(root, trees)
	if err != nil {
		return nil, fmt.Errorf("converting graph trees: %w", err)
	}

	return nl, nil
}

// convertTrees reads the tree map parsed from the go graph output and
// converts it to a protobom NodeList, capturing the graph structure.
func (d *Decomposer) convertTrees(root string, trees *map[string][]string) (nl *sbom.NodeList, err error) {
	// Create the new NodeList
	nl = sbom.NewNodeList()

	// Add the root package to anchor the
	// module's dependencies
	nl.AddRootNode(&sbom.Node{
		Id:   uuid.NewString(),
		Type: sbom.Node_PACKAGE,
		Name: root,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): goStringToPurl(root),
		},
	})

	// Run the recursive tree converter
	if err = d.convertTree(nl, []string{root}, trees, &map[string]struct{}{}); err != nil {
		return nil, fmt.Errorf("error running recursive conversion: %w", err)
	}

	return nl, nil
}

// convertTree takes a nodelist a component entry. It expects the component
// to already be expressed in a node in the node list (from its ancestor).
//
// The function returns the list of the components decendants to keep recursing.
// An empty list means the component is a leaf and no more recursion is needed.
func (d *Decomposer) convertTree(
	nl *sbom.NodeList, components []string, trees *map[string][]string, seen *map[string]struct{},
) error {
	// Cycle all the components
	for _, component := range components {
		if _, ok := (*seen)[component]; ok {
			continue
		}
		// All components should already exist in the probom
		// nodelist from a previous iterarion
		nodes := nl.GetNodesByIdentifier("purl", goStringToPurl(component))
		if len(nodes) == 0 {
			return fmt.Errorf("unable to find existing node for %s", goStringToPurl(component))
		}

		// If the component does not have an entry in the tree catalog
		// it means that it does not have any dependencies. Iterate to the next.
		if _, ok := (*trees)[component]; !ok {
			continue
		}

		// Process each of the component's dependencies:
		for _, subcomponent := range (*trees)[component] {
			name, version, ok := strings.Cut(subcomponent, "@")
			if !ok {
				return fmt.Errorf("unable to parse go graph entry: %q", subcomponent)
			}

			var subComponentNodes = nl.GetNodesByIdentifier("purl", goStringToPurl(subcomponent))

			var node *sbom.Node
			if len(subComponentNodes) > 0 {
				node = subComponentNodes[0]
			} else {
				node = &sbom.Node{
					Id:          uuid.NewString(),
					Type:        sbom.Node_PACKAGE,
					Name:        name,
					Version:     version,
					UrlDownload: fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip", name, version),
					Licenses:    []string{},
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): goStringToPurl(subcomponent),
					},
					Hashes: map[int32]string{},
					PrimaryPurpose: []sbom.Purpose{
						sbom.Purpose_LIBRARY,
					},
				}
			}

			// Add the node. This
			if err := nl.RelateNodeAtID(node, nodes[0].Id, sbom.Edge_dependsOn); err != nil {
				return fmt.Errorf("error relating node: %w", err)
			}
		}

		(*seen)[component] = struct{}{}
		// // Recurse to the subcomponent's children
		if err := d.convertTree(nl, (*trees)[component], trees, seen); err != nil {
			return err
		}

	}
	return nil
}

// readMainModule reads the module name from the go.mod file.
func (d *Decomposer) readMainModule(opts source.Options) (string, error) {
	data, err := os.ReadFile(filepath.Join(opts.WorkDir, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("reading go.mod: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "module ") {
			return strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "module ")), nil
		}
	}
	return "", errors.New("unable to read main module name")
}

// parseGoGraphparses the go graph as returned from the go command
func (d *Decomposer) parseGoGraph(data string) (*map[string][]string, error) {
	// Forst we
	trees := map[string][]string{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		linea := scanner.Text()
		srcLine, dstLine, ok := strings.Cut(linea, " ")
		if !ok {
			// I think this should never happen.
			continue
		}
		trees[srcLine] = append(trees[srcLine], dstLine)
	}
	return &trees, nil
}

// ExternalCommands returns the external commands required
func (d *Decomposer) ExternalCommands() []string {
	return []string{"go"}
}

// goStringToPurl converts a graph entry to a package url
func goStringToPurl(gostring string) string {
	name, version, ok := strings.Cut(gostring, "@")
	purl := fmt.Sprintf("pkg:golang/%s", name)
	if ok {
		purl = fmt.Sprintf("%s@%s", purl, version)
	}
	return purl
}

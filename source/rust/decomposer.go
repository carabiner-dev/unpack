// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/unpack/api/v1"
)

var _ api.Decomposer = (*Decomposer)(nil)

func New() *Decomposer {
	return &Decomposer{}
}

type Decomposer struct{}

var packageNameRegexString = `^(\d+)(\S+)\s(\S+)`
var packageNameRegex *regexp.Regexp

// These options not yet wired in
type Options struct {
	// These options match the cargo dependency names
	GenerateNormalDependencies bool
	GenerateBuildDependencies  bool
	GenerateDevDependencies    bool
}

// TODO(puerco): Enrich from https://crates.io/api/v1/crates/quote/1.0.35

func (d *Decomposer) Extract(opts *api.Options) (*sbom.NodeList, error) {
	var dopts = d.DefaultOptions().(Options)
	if lo := opts.GetDecomposerOptions(d); lo != nil {
		var ok bool
		dopts, ok = lo.(Options)
		if !ok {
			return nil, fmt.Errorf("invalid decomposer options type")
		}
	}
	var nl = sbom.NewNodeList()
	switch {
	case dopts.GenerateNormalDependencies:
		if err := d.parseDependencyTree(opts, nl, "normal"); err != nil {
			return nil, err

		}
	case dopts.GenerateDevDependencies:
		if err := d.parseDependencyTree(opts, nl, "dev"); err != nil {
			return nil, err

		}
	case dopts.GenerateBuildDependencies:
		if err := d.parseDependencyTree(opts, nl, "dev"); err != nil {
			return nil, err

		}
	}
	return nl, nil
}

// parseDependencyTree extracts dependencies from the rust source. This function
// takes a dependency type string: "normal", "dev", or "build" matching the cargo
// types.
func (d *Decomposer) parseDependencyTree(opts *api.Options, nl *sbom.NodeList, depType string) error {
	var typeParam string

	// Switch these to make sure we dont exec an unknown param:
	switch depType {
	case "normal", "dev", "build":
		typeParam = fmt.Sprintf("--edges=%s", depType)
	default:
		return fmt.Errorf("wrong dependency type")
	}

	// Build the command
	var cmd *command.Command
	if opts.WorkDir == "" {
		cmd = command.New("cargo", "tree", "--prefix=depth", "--no-dedupe", typeParam)
	} else {
		cmd = command.NewWithWorkDir(opts.WorkDir, "cargo", "tree", "--prefix=depth", "--no-dedupe", typeParam)
	}

	// Extract the dependency data
	output, err := cmd.RunSilentSuccessOutput()
	if err != nil {
		return fmt.Errorf("waiting for cargo output: %w", err)
	}

	seen := map[string]*sbom.Node{}

	if err := d.parseCargoOutput(nl, output.OutputTrimNL(), sbom.Edge_dependsOn, seen); err != nil {
		return fmt.Errorf("parsing cargo data: %w", err)
	}
	return nil
}

func (d *Decomposer) parseCargoOutput(nl *sbom.NodeList, data string, edgeType sbom.Edge_Type, seen map[string]*sbom.Node) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	if packageNameRegex == nil {
		packageNameRegex = regexp.MustCompile(packageNameRegexString)
	}

	var currentLevel = 0
	var depladder = map[int]*sbom.Node{}

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}

		matches := packageNameRegex.FindStringSubmatch(scanner.Text())
		if matches == nil {
			return fmt.Errorf("unable to parse cargo output %q %+v", scanner.Text(), matches)
		}

		version := matches[3]
		name := matches[2]
		level, err := strconv.Atoi(matches[1])
		if err != nil {
			return fmt.Errorf("error reading depth level")
		}
		currentLevel = level
		purl := fmt.Sprintf("pkg:cargo/%s@%s", name, version)

		// Reuse a node or generate a new one
		var node *sbom.Node
		if n, ok := seen[purl]; ok {
			node = n
		} else {
			node = &sbom.Node{
				Id:          uuid.NewString(),
				Type:        sbom.Node_PACKAGE,
				Name:        name,
				Version:     version,
				FileName:    name,
				UrlDownload: fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s/download", name, version),
				Identifiers: map[int32]string{
					int32(sbom.SoftwareIdentifierType_PURL): purl,
				},
				PrimaryPurpose: []sbom.Purpose{
					sbom.Purpose_LIBRARY,
				},
			}
			seen[purl] = node
		}
		depladder[level] = node
		if currentLevel > 0 {
			if err := nl.RelateNodeAtID(node, depladder[level-1].Id, edgeType); err != nil {
				return fmt.Errorf("linking %q to nodelist: %w", purl, err)
			}
		} else {
			nl.AddRootNode(node)
		}
	}
	return nil
}

func (d *Decomposer) DefaultOptions() any {
	return Options{
		GenerateNormalDependencies: true,
	}
}

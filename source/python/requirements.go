// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file reads requirements.txt, the format that predates lockfiles.
// What it yields depends on how the file was made. A compiled file
// (pip-compile, uv pip compile) is as good as a lock: exact pins, hashes,
// and "# via" annotations recording which requirement pulled in which — a
// real tree. A hand-written file declares constraints: entries without an
// exact pin become nodes without a version, and entries without provenance
// hang off the root. The reader takes what each line actually says and
// invents nothing.

// requirementEntry is one requirement plus what the file says about it.
type requirementEntry struct {
	requirement

	// Hashes are the sha256 values of the entry's --hash options. The
	// file does not say which artifact each belongs to, so only a lone
	// hash identifies the content.
	Hashes []string

	// Via lists what pulled this entry in, from the "# via" annotations
	// compiled files carry: requirement names, or "-r file" for a direct
	// requirement. Empty when the file has no annotations.
	Via []string
}

// readRequirementsFile reads a requirements file and the files it includes.
func readRequirementsFile(path string, visited map[string]bool) ([]*requirementEntry, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if visited[abs] {
		return nil, nil
	}
	visited[abs] = true

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading requirements: %w", err)
	}

	entries := []*requirementEntry{}
	for _, line := range logicalLines(string(data)) {
		switch {
		case strings.HasPrefix(line, "#"):
			// A via annotation belongs to the entry above it.
			if len(entries) > 0 {
				entries[len(entries)-1].Via = append(entries[len(entries)-1].Via, viaNames(line)...)
			}
		case strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement "):
			_, include, _ := strings.Cut(line, " ")
			included, err := readRequirementsFile(
				filepath.Join(filepath.Dir(path), strings.TrimSpace(include)), visited)
			if err != nil {
				return nil, err
			}
			entries = append(entries, included...)
		case strings.HasPrefix(line, "-"):
			// Editables point at local trees with no version to state, and
			// the rest are installer options: index URLs, constraints
			// files, binary policies. None of them declare a package.
			continue
		default:
			entry, err := parseRequirementLine(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// logicalLines joins the physical lines the file continues with a trailing
// backslash, and trims what remains.
func logicalLines(data string) []string {
	lines := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(data, "\\\n", " "), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// viaNames reads the names out of one "# via" annotation line: the inline
// form names one parent, the list form indents each on its own line.
func viaNames(line string) []string {
	text := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if text == "via" || text == "" {
		return nil
	}
	if name, found := strings.CutPrefix(text, "via "); found {
		text = name
	}
	// Annotation lines that are not via entries: the header comment.
	if strings.ContainsAny(text, ":/") && strings.HasPrefix(text, "uv ") {
		return nil
	}
	return []string{text}
}

// parseRequirementLine reads one requirement with its per-line options.
func parseRequirementLine(line string) (*requirementEntry, error) {
	spec := line
	entry := &requirementEntry{}

	if i := strings.Index(line, "--hash="); i >= 0 {
		spec = line[:i]
		for _, field := range strings.Fields(line[i:]) {
			if value, ok := strings.CutPrefix(field, "--hash=sha256:"); ok {
				entry.Hashes = append(entry.Hashes, value)
			}
		}
	}

	req, err := parseRequirement(strings.TrimSpace(spec))
	if err != nil {
		return nil, err
	}
	entry.requirement = *req
	return entry, nil
}

// extractRequirements builds the graph a requirements.txt states.
func (d *Decomposer) extractRequirements(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	entries, err := readRequirementsFile(filepath.Join(workDir, "requirements.txt"), map[string]bool{})
	if err != nil {
		return nil, err
	}

	dOpts := d.getOptions(opts)
	env, err := d.environment(dOpts, opts, fallbackPythonVersion)
	if err != nil {
		return nil, err
	}

	nl := sbom.NewNodeList()
	root := requirementsRoot(workDir, opts)
	nl.AddRootNode(root)

	// First the nodes: every entry whose marker holds in the environment.
	nodes := map[packageKey]*sbom.Node{}
	byName := map[string]*sbom.Node{}
	enrichable := map[packageKey]bool{}
	for _, entry := range entries {
		holds, err := env.Evaluate(entry.Marker)
		if err != nil {
			return nil, fmt.Errorf("evaluating marker on %s: %w", entry.Name, err)
		}
		if !holds {
			continue
		}
		if _, seen := byName[entry.Name]; seen {
			// Two entries of one name survive marker filtering only in a
			// hand-written file repeating itself; the first wins.
			continue
		}

		node := requirementNode(entry)
		nodes[packageKey{name: entry.Name, version: entry.Version}] = node
		byName[entry.Name] = node
		nl.AddNode(node)
		if entry.Version != "" && entry.URL == "" {
			enrichable[packageKey{name: entry.Name, version: entry.Version}] = true
		}
	}

	// Then the edges. A via annotation hangs the entry under what pulled
	// it in; everything else, and every parent the graph does not hold,
	// hangs off the root.
	for _, entry := range entries {
		node, ok := byName[entry.Name]
		if !ok {
			continue
		}
		related := false
		for _, via := range entry.Via {
			parent, isNode := byName[NormalizeName(via)]
			if !isNode || parent == node {
				continue
			}
			if err := nl.RelateNodeAtID(node, parent.GetId(), sbom.Edge_dependsOn); err != nil {
				return nil, err
			}
			related = true
		}
		if !related {
			if err := nl.RelateNodeAtID(node, root.GetId(), sbom.Edge_dependsOn); err != nil {
				return nil, err
			}
		}
	}

	if opts.Networking >= api.NetworkEssential {
		NewPyPIClient(dOpts.Concurrency).enrichNodes(nodes, enrichable)
	}
	return nl, nil
}

// requirementsRoot builds the root node. The format names no project, so
// the directory has to lend its name; the caller may know the version.
func requirementsRoot(workDir string, opts *api.DecomposerOptions) *sbom.Node {
	abs, err := filepath.Abs(workDir)
	if err != nil {
		abs = workDir
	}
	name := NormalizeName(filepath.Base(abs))

	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           name,
		Version:        opts.Version,
		Identifiers:    map[int32]string{},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	purlValue := "pkg:pypi/" + name
	if opts.Version != "" {
		purlValue = purl(name, opts.Version)
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlValue

	if opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

// requirementNode builds the node one entry states.
func requirementNode(entry *requirementEntry) *sbom.Node {
	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           entry.Name,
		Version:        entry.Version,
		Identifiers:    map[int32]string{},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	// An unpinned entry has no version to put in a purl: a range is a
	// constraint on a resolver, not a version.
	purlValue := "pkg:pypi/" + entry.Name
	if entry.Version != "" {
		purlValue = purl(entry.Name, entry.Version)
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlValue

	if entry.URL != "" {
		node.UrlDownload = entry.URL
		if strings.HasPrefix(entry.URL, "git+") {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  entry.URL,
				Type: sbom.ExternalReference_VCS,
			})
		}
	}

	// The file does not say which artifact each hash belongs to, so only
	// a lone hash identifies this entry's content. A compiled file lists
	// every artifact's hash, and picking one would be guessing.
	if len(entry.Hashes) == 1 {
		node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): entry.Hashes[0]}
	}
	return node
}

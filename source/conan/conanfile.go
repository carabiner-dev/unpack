// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package conan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// ManifestFile is the declarative form of a Conan recipe. The other form,
// conanfile.py, is a Python program and is not read.
const ManifestFile = "conanfile.txt"

// Manifest is what a conanfile.txt asks for.
type Manifest struct {
	// Requires are the packages the project is built from and links.
	Requires []*Reference

	// ToolRequires are the tools its build runs.
	ToolRequires []*Reference

	// TestRequires are what its tests need.
	TestRequires []*Reference
}

// ReadManifest reads a conanfile.txt.
func ReadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestFile, err)
	}
	return ParseManifest(data)
}

// ParseManifest reads the contents of a conanfile.txt: sections named in
// brackets, a requirement to a line in the three that hold them. The
// other sections, generators, options and layout, configure the build.
func ParseManifest(data []byte) (*Manifest, error) {
	manifest := &Manifest{}
	sections := map[string]*[]*Reference{
		"requires":      &manifest.Requires,
		"tool_requires": &manifest.ToolRequires,
		// What Conan 1 called tool requirements.
		"build_requires": &manifest.ToolRequires,
		"test_requires":  &manifest.TestRequires,
	}

	var current *[]*Reference
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for number := 1; scanner.Scan(); number++ {
		line := strings.TrimSpace(scanner.Text())
		switch {
		// Only a whole line is a comment: within a reference, # opens
		// the revision.
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !strings.Contains(line, "/"):
			current = sections[strings.TrimSpace(line[1:len(line)-1])]
		case current != nil:
			ref, err := ParseReference(line)
			if err != nil {
				return nil, fmt.Errorf("%s line %d: %w", ManifestFile, number, err)
			}
			*current = append(*current, ref)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestFile, err)
	}
	return manifest, nil
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file reads yarn.lock in the classic (v1) format: an indented block
// per resolution, keyed by the selectors that resolve to it —
//
//	wrappy@1, wrappy@^1.0.2:
//	  version "1.0.2"
//	  resolved "https://..."
//	  integrity sha512-...
//	  dependencies:
//	    once "^1.4.0"
//
// The lock records no dependency kinds at all: which requirements are dev
// or optional lives in package.json, and the graph builder reads it there.

// YarnLock is a parsed classic yarn.lock.
type YarnLock struct {
	// Entries maps every selector — "name@range", one block may serve
	// several — to its resolution. Edges resolve through this map: a
	// dependency states a name and a range, and the pair is a selector.
	Entries map[string]*YarnPackage
}

// YarnPackage is one resolved package.
type YarnPackage struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string

	// Dependencies and OptionalDependencies map names to the ranges the
	// package requires, resolvable through the lock's selectors.
	Dependencies         map[string]string
	OptionalDependencies map[string]string
}

// yarnBerryMarker is the block a berry (v2+) lock opens with. Both
// generations call the file yarn.lock, so the reader has to look inside.
var yarnBerryMarker = []byte("__metadata:")

// IsYarnBerry says whether lock data is the berry format rather than the
// classic one.
func IsYarnBerry(data []byte) bool {
	return bytes.Contains(data, yarnBerryMarker)
}

// ParseYarnLock reads a classic yarn.lock document.
func ParseYarnLock(data []byte) (*YarnLock, error) {
	if IsYarnBerry(data) {
		return nil, fmt.Errorf("this is a yarn berry (v2+) lockfile, which is not supported yet")
	}

	lock := &YarnLock{Entries: map[string]*YarnPackage{}}

	var current *YarnPackage
	var inDeps *map[string]string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		switch {
		// A block header: unindented selectors ending in a colon.
		case !strings.HasPrefix(line, " "):
			selectors, err := yarnSelectors(line)
			if err != nil {
				return nil, err
			}
			current = &YarnPackage{}
			inDeps = nil
			for _, selector := range selectors {
				name, err := yarnSelectorName(selector)
				if err != nil {
					return nil, err
				}
				current.Name = name
				lock.Entries[selector] = current
			}

		case current == nil:
			return nil, fmt.Errorf("unparseable yarn.lock: %q belongs to no block", trimmed)

		// The sub-block openers.
		case trimmed == "dependencies:":
			current.Dependencies = map[string]string{}
			inDeps = &current.Dependencies
		case trimmed == "optionalDependencies:":
			current.OptionalDependencies = map[string]string{}
			inDeps = &current.OptionalDependencies

		// A dependency line: deeper-indented name and range.
		case inDeps != nil && strings.HasPrefix(line, "    "):
			name, rang, err := yarnKeyValue(trimmed)
			if err != nil {
				return nil, err
			}
			(*inDeps)[name] = rang

		// A field of the block.
		default:
			inDeps = nil
			key, value, err := yarnKeyValue(trimmed)
			if err != nil {
				return nil, err
			}
			switch key {
			case "version":
				current.Version = value
			case "resolved":
				current.Resolved = value
			case "integrity":
				current.Integrity = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading yarn.lock: %w", err)
	}
	return lock, nil
}

// ReadYarnLock reads a yarn.lock from a directory.
func ReadYarnLock(workDir string) (*YarnLock, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "yarn.lock"))
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParseYarnLock(data)
}

// Resolve finds the package a name and range pair selects.
func (l *YarnLock) Resolve(name, rang string) *YarnPackage {
	return l.Entries[name+"@"+rang]
}

// yarnSelectors splits a block header into its selectors: comma-separated,
// each possibly quoted, the line ending in a colon.
func yarnSelectors(line string) ([]string, error) {
	header, ok := strings.CutSuffix(strings.TrimSpace(line), ":")
	if !ok {
		return nil, fmt.Errorf("unparseable yarn.lock header %q", line)
	}
	selectors := []string{}
	for _, selector := range strings.Split(header, ",") {
		selector = strings.Trim(strings.TrimSpace(selector), `"`)
		if selector == "" {
			return nil, fmt.Errorf("unparseable yarn.lock header %q", line)
		}
		selectors = append(selectors, selector)
	}
	return selectors, nil
}

// yarnSelectorName reads the package name out of a selector. A scoped name
// holds an @ of its own, so the name ends at the last one.
func yarnSelectorName(selector string) (string, error) {
	at := strings.LastIndex(selector, "@")
	if at <= 0 {
		return "", fmt.Errorf("unparseable yarn.lock selector %q", selector)
	}
	return selector[:at], nil
}

// yarnKeyValue splits a field or dependency line: a key, a space, and a
// usually-quoted value.
func yarnKeyValue(line string) (key, value string, err error) {
	key, value, found := strings.Cut(line, " ")
	if !found {
		return "", "", fmt.Errorf("unparseable yarn.lock line %q", line)
	}
	return strings.Trim(key, `"`), strings.Trim(strings.TrimSpace(value), `"`), nil
}

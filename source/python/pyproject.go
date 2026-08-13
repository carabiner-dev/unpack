// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"os"
	"sort"

	"github.com/BurntSushi/toml"
)

// This file reads the parts of pyproject.toml a Poetry graph needs and a
// uv graph does not: the project's identity and its direct dependencies. A
// uv lock records both; a poetry.lock records neither, so the manifest is
// where the graph's roots and first edges come from.
//
// Two manifest dialects say the same things: the standard [project] table
// (PEP 621), and the legacy [tool.poetry] one older Poetry projects use.
// Groups may come from [tool.poetry.group.*] or the standard
// [dependency-groups] (PEP 735).

// PyProject is a parsed pyproject.toml, reduced to what the graph needs.
type PyProject struct {
	Project struct {
		Name                 string              `toml:"name"`
		Version              string              `toml:"version"`
		RequiresPython       string              `toml:"requires-python"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`

	// DependencyGroups is the standard groups table (PEP 735). Entries are
	// requirement strings, or include tables this reader skips.
	DependencyGroups map[string][]any `toml:"dependency-groups"`

	Tool struct {
		Poetry struct {
			Name         string              `toml:"name"`
			Version      string              `toml:"version"`
			Dependencies map[string]any      `toml:"dependencies"`
			Extras       map[string][]string `toml:"extras"`
			Group        map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
			// DevDependencies is the oldest spelling of the dev group.
			DevDependencies map[string]any `toml:"dev-dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// ReadPyProject reads a pyproject.toml file.
func ReadPyProject(path string) (*PyProject, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	project := &PyProject{}
	if err := toml.Unmarshal(data, project); err != nil {
		return nil, fmt.Errorf("parsing pyproject.toml: %w", err)
	}
	return project, nil
}

// RootName returns the project's name, normalized, from whichever table
// states it.
func (p *PyProject) RootName() string {
	if p.Project.Name != "" {
		return NormalizeName(p.Project.Name)
	}
	return NormalizeName(p.Tool.Poetry.Name)
}

// RootVersion returns the project's version from whichever table states it.
func (p *PyProject) RootVersion() string {
	if p.Project.Version != "" {
		return p.Project.Version
	}
	return p.Tool.Poetry.Version
}

// MainDependencies returns the project's direct runtime dependencies.
//
// In the legacy table, python is a pseudo-dependency and an entry marked
// optional belongs to the extras rather than to the runtime set.
func (p *PyProject) MainDependencies() ([]*requirement, error) {
	if len(p.Project.Dependencies) > 0 {
		return parseRequirements(p.Project.Dependencies)
	}

	deps := []*requirement{}
	for _, name := range sortedTableKeys(p.Tool.Poetry.Dependencies) {
		if NormalizeName(name) == "python" || poetryEntryIsOptional(p.Tool.Poetry.Dependencies[name]) {
			continue
		}
		deps = append(deps, legacyRequirement(name, p.Tool.Poetry.Dependencies[name]))
	}
	return deps, nil
}

// GroupDependencies returns the direct dependencies of every dependency
// group, whichever of the three spellings declares them.
func (p *PyProject) GroupDependencies() (map[string][]*requirement, error) {
	groups := map[string][]*requirement{}

	for name, group := range p.Tool.Poetry.Group {
		for _, dep := range sortedTableKeys(group.Dependencies) {
			groups[name] = append(groups[name], legacyRequirement(dep, group.Dependencies[dep]))
		}
	}
	if len(p.Tool.Poetry.DevDependencies) > 0 {
		for _, dep := range sortedTableKeys(p.Tool.Poetry.DevDependencies) {
			groups["dev"] = append(groups["dev"], legacyRequirement(dep, p.Tool.Poetry.DevDependencies[dep]))
		}
	}

	for name, entries := range p.DependencyGroups {
		for _, entry := range entries {
			line, ok := entry.(string)
			if !ok {
				// An include table pulls one group into another; the
				// included group's packages are already reachable through
				// its own name, so skipping it loses no package.
				continue
			}
			req, err := parseRequirement(line)
			if err != nil {
				return nil, fmt.Errorf("group %s: %w", name, err)
			}
			groups[name] = append(groups[name], req)
		}
	}
	return groups, nil
}

// ExtraDependencies returns the direct dependencies of every extra.
func (p *PyProject) ExtraDependencies() (map[string][]*requirement, error) {
	extras := map[string][]*requirement{}

	for name, lines := range p.Project.OptionalDependencies {
		reqs, err := parseRequirements(lines)
		if err != nil {
			return nil, fmt.Errorf("extra %s: %w", name, err)
		}
		extras[NormalizeName(name)] = reqs
	}

	// The legacy extras table lists names whose requirements sit, marked
	// optional, in the main dependency table.
	for name, members := range p.Tool.Poetry.Extras {
		for _, member := range members {
			req, err := parseRequirement(member)
			if err != nil {
				return nil, fmt.Errorf("extra %s: %w", name, err)
			}
			extras[NormalizeName(name)] = append(extras[NormalizeName(name)], req)
		}
	}
	return extras, nil
}

func parseRequirements(lines []string) ([]*requirement, error) {
	reqs := make([]*requirement, 0, len(lines))
	for _, line := range lines {
		req, err := parseRequirement(line)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// legacyRequirement reads an entry of a [tool.poetry.dependencies]-style
// table, whose values are constraints: a version string, or a table that
// may carry markers and extras.
func legacyRequirement(name string, constraint any) *requirement {
	req := &requirement{Name: NormalizeName(name)}
	table, ok := constraint.(map[string]any)
	if !ok {
		return req
	}
	if marker, ok := table["markers"].(string); ok {
		req.Marker = marker
	}
	if extras, ok := table["extras"].([]any); ok {
		for _, extra := range extras {
			if s, ok := extra.(string); ok {
				req.Extras = append(req.Extras, NormalizeName(s))
			}
		}
	}
	return req
}

func poetryEntryIsOptional(constraint any) bool {
	table, ok := constraint.(map[string]any)
	if !ok {
		return false
	}
	optional, isBool := table["optional"].(bool)
	return isBool && optional
}

func sortedTableKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

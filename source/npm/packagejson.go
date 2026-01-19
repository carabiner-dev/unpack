// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PackageJSON represents the structure of a package.json file.
type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Description          string            `json:"description,omitempty"`
	License              string            `json:"license,omitempty"`
	Homepage             string            `json:"homepage,omitempty"`
	Repository           *Repository       `json:"repository,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
}

// Repository represents the repository field in package.json.
type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// UnmarshalJSON handles both string and object forms of repository.
func (r *Repository) UnmarshalJSON(data []byte) error {
	// Try string form first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		r.URL = s
		return nil
	}

	// Try object form
	type repoObj Repository
	var obj repoObj
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*r = Repository(obj)
	return nil
}

// DependencyType represents the type of dependency relationship.
type DependencyType int

const (
	DepTypeNormal DependencyType = iota
	DepTypeDev
	DepTypePeer
	DepTypeOptional
)

// String returns a string representation of the dependency type.
func (dt DependencyType) String() string {
	switch dt {
	case DepTypeNormal:
		return "normal"
	case DepTypeDev:
		return "dev"
	case DepTypePeer:
		return "peer"
	case DepTypeOptional:
		return "optional"
	default:
		return "unknown"
	}
}

// ParsePackageJSON parses a package.json file from the given directory.
func ParsePackageJSON(dir string) (*PackageJSON, error) {
	jsonPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	return ParsePackageJSONData(data)
}

// ParsePackageJSONData parses package.json content from bytes.
func ParsePackageJSONData(data []byte) (*PackageJSON, error) {
	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	return &pkg, nil
}

// GetDirectDependencies returns a map of dependency names to their types.
func (pj *PackageJSON) GetDirectDependencies() map[string]DependencyType {
	deps := make(map[string]DependencyType)

	// Normal dependencies
	for name := range pj.Dependencies {
		deps[name] = DepTypeNormal
	}

	// Dev dependencies
	for name := range pj.DevDependencies {
		deps[name] = DepTypeDev
	}

	// Peer dependencies
	for name := range pj.PeerDependencies {
		// Don't override if already set
		if _, exists := deps[name]; !exists {
			deps[name] = DepTypePeer
		}
	}

	// Optional dependencies
	for name := range pj.OptionalDependencies {
		// Don't override if already set
		if _, exists := deps[name]; !exists {
			deps[name] = DepTypeOptional
		}
	}

	return deps
}

// GetAllDependencyNames returns all direct dependency names.
func (pj *PackageJSON) GetAllDependencyNames() []string {
	seen := make(map[string]bool)
	var names []string

	for name := range pj.Dependencies {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for name := range pj.DevDependencies {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for name := range pj.PeerDependencies {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for name := range pj.OptionalDependencies {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	return names
}

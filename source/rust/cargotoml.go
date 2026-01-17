// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// CargoToml represents the structure of a Cargo.toml file.
type CargoToml struct {
	Package           PackageInfo               `toml:"package"`
	Dependencies      map[string]DependencySpec `toml:"dependencies"`
	DevDependencies   map[string]DependencySpec `toml:"dev-dependencies"`
	BuildDependencies map[string]DependencySpec `toml:"build-dependencies"`
	Target            map[string]TargetDeps     `toml:"target"`
	Workspace         *WorkspaceInfo            `toml:"workspace"`
}

// PackageInfo contains package metadata from Cargo.toml.
type PackageInfo struct {
	Name        string `toml:"name"`
	Version     string `toml:"version"`
	Edition     string `toml:"edition"`
	Description string `toml:"description"`
	License     string `toml:"license"`
	Homepage    string `toml:"homepage"`
	Repository  string `toml:"repository"`
}

// TargetDeps represents target-specific dependencies.
type TargetDeps struct {
	Dependencies      map[string]DependencySpec `toml:"dependencies"`
	DevDependencies   map[string]DependencySpec `toml:"dev-dependencies"`
	BuildDependencies map[string]DependencySpec `toml:"build-dependencies"`
}

// WorkspaceInfo represents workspace configuration.
type WorkspaceInfo struct {
	Members      []string                  `toml:"members"`
	Dependencies map[string]DependencySpec `toml:"dependencies"`
}

// DependencySpec represents a dependency specification in Cargo.toml.
// Dependencies can be specified in multiple formats:
// - Simple: "1.0"
// - Table: { version = "1.0", features = ["foo"] }
type DependencySpec struct {
	Version  string   `toml:"version"`
	Path     string   `toml:"path"`
	Git      string   `toml:"git"`
	Branch   string   `toml:"branch"`
	Tag      string   `toml:"tag"`
	Rev      string   `toml:"rev"`
	Features []string `toml:"features"`
	Optional bool     `toml:"optional"`

	// For simple string dependencies
	simpleVersion string
}

// UnmarshalTOML implements custom unmarshaling for dependency specs.
func (ds *DependencySpec) UnmarshalTOML(data any) error {
	switch v := data.(type) {
	case string:
		// Simple version string: anyhow = "1.0"
		ds.simpleVersion = v
		ds.Version = v
		return nil
	case map[string]any:
		// Table format: { version = "1.0", features = [...] }
		if ver, ok := v["version"].(string); ok {
			ds.Version = ver
		}
		if path, ok := v["path"].(string); ok {
			ds.Path = path
		}
		if git, ok := v["git"].(string); ok {
			ds.Git = git
		}
		if branch, ok := v["branch"].(string); ok {
			ds.Branch = branch
		}
		if tag, ok := v["tag"].(string); ok {
			ds.Tag = tag
		}
		if rev, ok := v["rev"].(string); ok {
			ds.Rev = rev
		}
		if opt, ok := v["optional"].(bool); ok {
			ds.Optional = opt
		}
		if features, ok := v["features"].([]any); ok {
			for _, f := range features {
				if fs, ok := f.(string); ok {
					ds.Features = append(ds.Features, fs)
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("unexpected dependency format: %T", data)
	}
}

// GetVersion returns the version specification.
func (ds *DependencySpec) GetVersion() string {
	if ds.simpleVersion != "" {
		return ds.simpleVersion
	}
	return ds.Version
}

// IsLocalPath returns true if this is a path dependency.
func (ds *DependencySpec) IsLocalPath() bool {
	return ds.Path != ""
}

// IsGit returns true if this is a git dependency.
func (ds *DependencySpec) IsGit() bool {
	return ds.Git != ""
}

// DependencyType represents the type of dependency relationship.
type DependencyType int

const (
	DepTypeNormal DependencyType = iota
	DepTypeDev
	DepTypeBuild
)

// String returns a string representation of the dependency type.
func (dt DependencyType) String() string {
	switch dt {
	case DepTypeNormal:
		return "normal"
	case DepTypeDev:
		return "dev"
	case DepTypeBuild:
		return "build"
	default:
		return "unknown"
	}
}

// ParseCargoToml parses a Cargo.toml file from the given directory.
func ParseCargoToml(dir string) (*CargoToml, error) {
	tomlPath := filepath.Join(dir, "Cargo.toml")
	data, err := os.ReadFile(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("reading Cargo.toml: %w", err)
	}

	return ParseCargoTomlData(data)
}

// ParseCargoTomlData parses Cargo.toml content from bytes.
func ParseCargoTomlData(data []byte) (*CargoToml, error) {
	var manifest CargoToml
	if _, err := toml.Decode(string(data), &manifest); err != nil {
		return nil, fmt.Errorf("parsing Cargo.toml: %w", err)
	}

	return &manifest, nil
}

// GetDirectDependencies returns a map of dependency names to their types.
// This includes dependencies from all sections and target-specific dependencies.
func (ct *CargoToml) GetDirectDependencies() map[string]DependencyType {
	deps := make(map[string]DependencyType)

	// Normal dependencies
	for name := range ct.Dependencies {
		deps[name] = DepTypeNormal
	}

	// Dev dependencies
	for name := range ct.DevDependencies {
		deps[name] = DepTypeDev
	}

	// Build dependencies
	for name := range ct.BuildDependencies {
		deps[name] = DepTypeBuild
	}

	// Target-specific dependencies
	for _, target := range ct.Target {
		for name := range target.Dependencies {
			// Don't override if already set (normal deps take precedence)
			if _, exists := deps[name]; !exists {
				deps[name] = DepTypeNormal
			}
		}
		for name := range target.DevDependencies {
			if _, exists := deps[name]; !exists {
				deps[name] = DepTypeDev
			}
		}
		for name := range target.BuildDependencies {
			if _, exists := deps[name]; !exists {
				deps[name] = DepTypeBuild
			}
		}
	}

	return deps
}

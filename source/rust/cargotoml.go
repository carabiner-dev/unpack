// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

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

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rust

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

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

	// workspaceRenames maps the names of the workspace's shared
	// dependencies to the crates they rename, for a member manifest that
	// inherits them ("name = { workspace = true }") and so does not state
	// the crate itself.
	workspaceRenames map[string]string
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

	// Package is the crate's real name when the dependency is declared
	// under another: tmp = { package = "tempfile" }. The table's key is
	// then only what the code calls it; the lock knows the crate by this
	// name.
	Package string `toml:"package"`

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
		if pkg, ok := v["package"].(string); ok {
			ds.Package = pkg
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

// maxMemberManifests bounds how many manifests ReadMemberManifests reads.
const maxMemberManifests = 2000

// ReadMemberManifests reads the manifests of the local packages of the
// project rooted at dir, other than the root manifest itself: the members
// its workspace table lists, patterns expanded, and whatever those and the
// root require by path, as long as it sits inside dir. They are returned
// by the name of the package each describes.
//
// A member's own manifest is what says which of its dependencies are for
// development or for building, which Cargo.lock does not record. A
// manifest that cannot be read or parsed is skipped: its package's
// dependencies are then all taken as normal ones.
func ReadMemberManifests(dir string, root *CargoToml) map[string]*CargoToml {
	members := map[string]*CargoToml{}
	if root == nil {
		return members
	}

	// Directories to read, relative to dir, each once.
	queue := []string{}
	seen := map[string]struct{}{".": {}}
	enqueue := func(rel string) {
		rel = filepath.Clean(rel)
		if !filepath.IsLocal(rel) {
			return
		}
		if _, dup := seen[rel]; dup {
			return
		}
		seen[rel] = struct{}{}
		queue = append(queue, rel)
	}
	enqueuePaths := func(from string, manifest *CargoToml) {
		manifest.eachDependency(func(_ string, spec *DependencySpec) {
			if spec.Path != "" {
				enqueue(filepath.Join(from, filepath.FromSlash(spec.Path)))
			}
		})
	}

	if root.Workspace != nil {
		for _, pattern := range root.Workspace.Members {
			pattern = filepath.FromSlash(pattern)
			if !filepath.IsLocal(pattern) {
				continue
			}
			matches, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				continue
			}
			sort.Strings(matches)
			for _, match := range matches {
				if rel, err := filepath.Rel(dir, match); err == nil {
					enqueue(rel)
				}
			}
		}
	}
	enqueuePaths(".", root)

	for read := 0; len(queue) > 0 && read < maxMemberManifests; read++ {
		rel := queue[0]
		queue = queue[1:]

		manifest, err := ParseCargoToml(filepath.Join(dir, rel))
		if err != nil || manifest.Package.Name == "" {
			continue
		}
		if _, dup := members[manifest.Package.Name]; !dup {
			members[manifest.Package.Name] = manifest
		}
		enqueuePaths(rel, manifest)
	}
	return members
}

// eachDependency calls fn for every dependency the manifest declares, in
// any section.
func (ct *CargoToml) eachDependency(fn func(name string, spec *DependencySpec)) {
	sections := make([]map[string]DependencySpec, 0, 3+3*len(ct.Target))
	sections = append(sections, ct.Dependencies, ct.DevDependencies, ct.BuildDependencies)
	for _, target := range ct.Target {
		sections = append(sections, target.Dependencies, target.DevDependencies, target.BuildDependencies)
	}
	for _, section := range sections {
		for name := range section {
			spec := section[name]
			fn(name, &spec)
		}
	}
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
//
// The names are the crates', which is how Cargo.lock refers to them: a
// dependency declared under another name is listed by the crate it
// renames.
//
// A crate may be declared in more than one section, and the map holds one
// type per name: the one that puts the crate furthest into what is built.
// A normal dependency is part of the package whatever else it is used
// for, and a build dependency is compiled to build it, where a dev
// dependency only serves its tests.
func (ct *CargoToml) GetDirectDependencies() map[string]DependencyType {
	deps := make(map[string]DependencyType)
	declare := func(section map[string]DependencySpec, depType DependencyType) {
		for name := range section {
			if renamed := section[name].Package; renamed != "" {
				name = renamed
			} else if renamed := ct.workspaceRenames[name]; renamed != "" {
				name = renamed
			}
			if _, exists := deps[name]; !exists {
				deps[name] = depType
			}
		}
	}

	// Each type in turn, strongest first, across the package's own
	// sections and the target-specific ones.
	declare(ct.Dependencies, DepTypeNormal)
	for _, target := range ct.Target {
		declare(target.Dependencies, DepTypeNormal)
	}
	declare(ct.BuildDependencies, DepTypeBuild)
	for _, target := range ct.Target {
		declare(target.BuildDependencies, DepTypeBuild)
	}
	declare(ct.DevDependencies, DepTypeDev)
	for _, target := range ct.Target {
		declare(target.DevDependencies, DepTypeDev)
	}

	return deps
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// This file reads what a .NET project asks for when it has no lockfile:
// the package references of its project file, the versions a repository
// manages centrally, and the older packages.config.
//
// These say what the project asks for, and not what that resolved to.
// The packages those packages bring in are not in them, and a version
// is the one asked for: the lowest NuGet may pick.

// Files read beside, or above, a project.
const (
	// PackagesConfigFile lists the packages of a project of the older
	// kind, each at the exact version installed.
	PackagesConfigFile = "packages.config"

	// CentralVersionsFile holds the versions a repository manages
	// centrally. It is at the root of the repository or of a part of it,
	// above the projects it governs.
	CentralVersionsFile = "Directory.Packages.props"

	// buildPropsFile and buildTargetsFile hold what the projects below
	// them share: properties, versions among them, and package
	// references every one of those projects then has.
	buildPropsFile   = "Directory.Build.props"
	buildTargetsFile = "Directory.Build.targets"
)

// Reference is one package a project file asks for.
type Reference struct {
	ID string

	// Requested is the version asked for, as written and with the
	// properties it uses filled in: a version, a range ("[1.0, 2.0)") or
	// a floating one ("8.*"). Empty when the project states none and no
	// central file does.
	Requested string

	// Private says the package does not flow to what uses the project:
	// PrivateAssets is "all". Analyzers, source generators and build
	// tooling are referenced that way.
	Private bool

	// Condition is the condition the reference is under, its own or its
	// item group's: most often a target framework.
	Condition string
}

// Version returns the version the reference pins, when what it asks for
// is one version: a plain version, which NuGet resolves to itself unless
// something else in the graph asks for a higher one, or an exact one in
// brackets. A range or a floating version resolves to something only a
// restore knows, and gives none.
func (r *Reference) Version() string {
	requested := strings.TrimSpace(r.Requested)
	if exact, ok := strings.CutPrefix(requested, "["); ok {
		if inner, ok := strings.CutSuffix(exact, "]"); ok && plainVersion.MatchString(strings.TrimSpace(inner)) {
			return strings.TrimSpace(inner)
		}
		return ""
	}
	if plainVersion.MatchString(requested) {
		return requested
	}
	return ""
}

var plainVersion = regexp.MustCompile(`^\d+(\.\d+){0,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Project is what an MSBuild file says of a project's packages. The same
// reader serves a project file and the props files above it.
type Project struct {
	// References are the PackageReference items, and Global the
	// GlobalPackageReference items of a central file, which every
	// project below it has.
	References []*Reference
	Global     []*Reference

	// Central are the versions a central file gives, by package id in
	// lower case.
	Central map[string]string

	// ProjectReferences are the other projects referenced, by the path
	// written.
	ProjectReferences []string

	// Properties are the properties defined, by name in lower case.
	Properties map[string]string
}

type rawItem struct {
	Include         string `xml:"Include,attr"`
	Version         string `xml:"Version,attr"`
	VersionOverride string `xml:"VersionOverride,attr"`
	PrivateAssets   string `xml:"PrivateAssets,attr"`
	Condition       string `xml:"Condition,attr"`

	VersionElement       string `xml:"Version"`
	PrivateAssetsElement string `xml:"PrivateAssets"`
}

// utf8BOM opens a file a tool on Windows wrote.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ReadProject reads an MSBuild file: a project, or a props file.
func ReadProject(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	return ParseProject(data)
}

// ParseProject reads the contents of an MSBuild file. Items are read
// wherever they are in it, in an item group or in the branches of a
// Choose, each with the conditions it is under.
func ParseProject(data []byte) (*Project, error) {
	project := &Project{Central: map[string]string{}, Properties: map[string]string{}}
	decoder := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, utf8BOM)))

	type frame struct{ name, condition string }
	stack := []frame{}
	conditions := func(own string) string {
		parts := []string{}
		for _, f := range stack {
			if f.condition != "" {
				parts = append(parts, f.condition)
			}
		}
		if own != "" {
			parts = append(parts, own)
		}
		return strings.Join(parts, " and ")
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing MSBuild file: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			name := element.Name.Local
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].name
			}
			switch {
			case name == "PackageReference" || name == "GlobalPackageReference" || name == "PackageVersion" || name == "ProjectReference":
				item := &rawItem{}
				if err := decoder.DecodeElement(item, &element); err != nil {
					return nil, fmt.Errorf("parsing MSBuild file: %w", err)
				}
				project.addItem(name, item, conditions(item.Condition))
			case parent == "PropertyGroup":
				var value string
				if err := decoder.DecodeElement(&value, &element); err != nil {
					// A property holding markup is no version.
					continue
				}
				project.Properties[strings.ToLower(name)] = strings.TrimSpace(value)
			default:
				condition := ""
				for _, attribute := range element.Attr {
					if attribute.Name.Local == "Condition" {
						condition = attribute.Value
					}
				}
				stack = append(stack, frame{name, condition})
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return project, nil
}

// addItem records one item.
func (p *Project) addItem(kind string, item *rawItem, condition string) {
	include := strings.TrimSpace(item.Include)
	if include == "" {
		// An Update or a Remove changes an item declared elsewhere.
		return
	}
	version := firstOf(item.VersionOverride, item.Version, item.VersionElement)
	private := strings.EqualFold(strings.TrimSpace(firstOf(item.PrivateAssets, item.PrivateAssetsElement)), "all")

	switch kind {
	case "ProjectReference":
		p.ProjectReferences = append(p.ProjectReferences, include)
	case "PackageVersion":
		p.Central[strings.ToLower(include)] = version
	case "GlobalPackageReference":
		// Global references are private by definition.
		p.Global = append(p.Global, &Reference{ID: include, Requested: version, Private: true, Condition: condition})
	default:
		p.References = append(p.References, &Reference{ID: include, Requested: version, Private: private, Condition: condition})
	}
}

func firstOf(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

var propertyReference = regexp.MustCompile(`\$\(([A-Za-z0-9_.]+)\)`)

// expandProperties fills in the properties a value uses, $(Name), from
// the ones given, the nearest first. A value using a property none of
// them defines is left as written.
func expandProperties(value string, sources ...map[string]string) string {
	for range 5 {
		if !strings.Contains(value, "$(") {
			break
		}
		value = propertyReference.ReplaceAllStringFunc(value, func(ref string) string {
			name := strings.ToLower(propertyReference.FindStringSubmatch(ref)[1])
			for _, source := range sources {
				if replacement, ok := source[name]; ok {
					return replacement
				}
			}
			return ref
		})
	}
	return value
}

// findAbove looks for a file at a directory and then at those above it,
// up to the root of the git repository the directory is in, and returns
// nothing when it is not there.
func findAbove(dir, name string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(abs, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		if _, err := os.Lstat(filepath.Join(abs, ".git")); err == nil {
			return ""
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
}

// ConfigPackage is one package of a packages.config.
type ConfigPackage struct {
	ID          string `xml:"id,attr"`
	Version     string `xml:"version,attr"`
	Framework   string `xml:"targetFramework,attr"`
	Development bool   `xml:"developmentDependency,attr"`
}

// ReadPackagesConfig reads a packages.config: every package installed
// for a project of the older kind, at its exact version. It lists the
// packages those bring in beside them, without saying which brought
// which.
func ReadPackagesConfig(path string) ([]*ConfigPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", PackagesConfigFile, err)
	}
	var config struct {
		Packages []*ConfigPackage `xml:"package"`
	}
	if err := xml.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &config); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", PackagesConfigFile, err)
	}
	packages := config.Packages[:0]
	for _, pkg := range config.Packages {
		if pkg != nil && pkg.ID != "" {
			packages = append(packages, pkg)
		}
	}
	return packages, nil
}

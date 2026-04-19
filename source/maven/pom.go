// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/encoding/ianaindex"
)

// POM represents a Maven POM file.
type POM struct {
	XMLName              xml.Name              `xml:"project"`
	ModelVersion         string                `xml:"modelVersion"`
	Parent               *Parent               `xml:"parent"`
	GroupID              string                `xml:"groupId"`
	ArtifactID           string                `xml:"artifactId"`
	Version              string                `xml:"version"`
	Packaging            string                `xml:"packaging"`
	Name                 string                `xml:"name"`
	Description          string                `xml:"description"`
	URL                  string                `xml:"url"`
	Licenses             []License             `xml:"licenses>license"`
	Properties           Properties            `xml:"properties"`
	DependencyManagement *DependencyManagement `xml:"dependencyManagement"`
	Dependencies         []Dependency          `xml:"dependencies>dependency"`
	Modules              []string              `xml:"modules>module"`
	Repositories         []Repository          `xml:"repositories>repository"`
}

// EffectiveGroupID returns the POM's groupId, falling back to parent's.
func (p *POM) EffectiveGroupID() string {
	if p.GroupID != "" {
		return p.GroupID
	}
	if p.Parent != nil {
		return p.Parent.GroupID
	}
	return ""
}

// EffectiveVersion returns the POM's version, falling back to parent's.
func (p *POM) EffectiveVersion() string {
	if p.Version != "" {
		return p.Version
	}
	if p.Parent != nil {
		return p.Parent.Version
	}
	return ""
}

// Parent represents a POM parent reference.
type Parent struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

// Dependency represents a Maven dependency declaration.
type Dependency struct {
	GroupID    string      `xml:"groupId"`
	ArtifactID string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Scope      string      `xml:"scope"`
	Type       string      `xml:"type"`
	Classifier string      `xml:"classifier"`
	Optional   string      `xml:"optional"`
	Exclusions []Exclusion `xml:"exclusions>exclusion"`
}

const (
	ScopeCompile  = "compile"
	ScopeRuntime  = "runtime"
	ScopeTest     = "test"
	ScopeProvided = "provided"
	ScopeSystem   = "system"
	ScopeImport   = "import"

	// DefaultType is the default Maven artifact type.
	DefaultType = "jar"
)

// IsOptional returns true if the dependency is marked optional.
func (d *Dependency) IsOptional() bool {
	return d.Optional == "true"
}

// EffectiveScope returns the dependency's scope, defaulting to "compile".
func (d *Dependency) EffectiveScope() string {
	if d.Scope == "" {
		return ScopeCompile
	}
	return d.Scope
}

// EffectiveType returns the dependency's type, defaulting to "jar".
func (d *Dependency) EffectiveType() string {
	if d.Type == "" {
		return DefaultType
	}
	return d.Type
}

// Key returns "groupId:artifactId" used for mediation lookups.
func (d *Dependency) Key() string {
	return d.GroupID + ":" + d.ArtifactID
}

// Exclusion represents a dependency exclusion.
type Exclusion struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

// Matches returns true if the exclusion matches the given coordinates.
// Supports wildcard "*" for both groupId and artifactId.
func (e *Exclusion) Matches(groupID, artifactID string) bool {
	gMatch := e.GroupID == "*" || e.GroupID == groupID
	aMatch := e.ArtifactID == "*" || e.ArtifactID == artifactID
	return gMatch && aMatch
}

// License represents a license declaration in a POM.
type License struct {
	Name         string `xml:"name"`
	URL          string `xml:"url"`
	Distribution string `xml:"distribution"`
	Comments     string `xml:"comments"`
}

// DependencyManagement holds managed dependency versions and settings.
type DependencyManagement struct {
	Dependencies []Dependency `xml:"dependencies>dependency"`
}

// Repository represents a Maven repository declaration.
type Repository struct {
	ID        string            `xml:"id"`
	URL       string            `xml:"url"`
	Name      string            `xml:"name"`
	Snapshots *RepositoryPolicy `xml:"snapshots"`
	Releases  *RepositoryPolicy `xml:"releases"`
}

// SnapshotsEnabled returns true if this repository serves snapshot artifacts.
// Maven defaults to false for snapshots.
func (r Repository) SnapshotsEnabled() bool {
	if r.Snapshots == nil {
		return false
	}
	return strings.EqualFold(r.Snapshots.Enabled, "true")
}

// ReleasesEnabled returns true if this repository serves release artifacts.
// Maven defaults to true for releases.
func (r Repository) ReleasesEnabled() bool {
	if r.Releases == nil {
		return true
	}
	return !strings.EqualFold(r.Releases.Enabled, "false")
}

// RepositoryPolicy controls whether a repository serves releases or snapshots.
type RepositoryPolicy struct {
	Enabled string `xml:"enabled"`
}

// Properties is a map of Maven property key-value pairs.
// It requires custom XML unmarshaling because properties are
// arbitrary child elements: <jackson.version>2.15</jackson.version>
type Properties map[string]string

// UnmarshalXML decodes Maven properties from XML.
func (p *Properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*p = Properties{}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return fmt.Errorf("decoding property %s: %w", t.Name.Local, err)
			}
			(*p)[t.Name.Local] = value
		case xml.EndElement:
			return nil
		}
	}
}

// ParsePomXML reads and parses a pom.xml file from the given directory.
func ParsePomXML(dir string) (*POM, error) {
	pomPath := filepath.Join(dir, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, fmt.Errorf("reading pom.xml: %w", err)
	}
	return ParsePomXMLData(data)
}

// ParsePomXMLData parses POM content from raw bytes.
// Handles non-UTF-8 encodings (e.g., ISO-8859-1) commonly found in Maven POMs.
func ParsePomXMLData(data []byte) (*POM, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = charsetReader

	var pom POM
	if err := decoder.Decode(&pom); err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}
	return &pom, nil
}

// charsetReader returns a reader that converts from the named charset to UTF-8.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	enc, err := ianaindex.IANA.Encoding(charset)
	if err != nil {
		return nil, fmt.Errorf("unsupported charset %q: %w", charset, err)
	}
	if enc == nil {
		// nil encoding means UTF-8
		return input, nil
	}
	return enc.NewDecoder().Reader(input), nil
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gradle

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// CatalogFile is where a build keeps its version catalog, relative to its
// root: the libraries and plugins its build scripts may ask for by
// alias, each at the version the build asks for.
const CatalogFile = "gradle/libs.versions.toml"

// Catalog is a version catalog.
//
// It declares what a build's scripts may use and not what they do use: a
// script asks for a library by its alias (libs.guava), and scripts are
// programs. It states requested versions, not resolved ones, and none of
// what the libraries bring in.
type Catalog struct {
	Libraries []*CatalogLibrary
	Plugins   []*CatalogPlugin
}

// CatalogLibrary is one library of a catalog.
type CatalogLibrary struct {
	Alias string
	Group string
	Name  string

	// Version is the version asked for when it is one version, and
	// Requested what the catalog writes when it is not: a range, a
	// preference, or nothing at all for a library a platform gives a
	// version to.
	Version   string
	Requested string
}

// CatalogPlugin is one plugin of a catalog.
type CatalogPlugin struct {
	Alias     string
	ID        string
	Version   string
	Requested string
}

// ReadCatalog reads a version catalog.
func ReadCatalog(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading version catalog: %w", err)
	}
	return ParseCatalog(data)
}

// ParseCatalog reads the contents of a version catalog: its [versions],
// [libraries] and [plugins] tables. Its [bundles] group libraries under a
// name and add none.
//
// A library is written as "group:name:version", or as a table naming its
// module, or its group and name, and a version; a version is a string, a
// reference to an entry of [versions], or a table of constraints.
func ParseCatalog(data []byte) (*Catalog, error) {
	var raw struct {
		Versions  map[string]any `toml:"versions"`
		Libraries map[string]any `toml:"libraries"`
		Plugins   map[string]any `toml:"plugins"`
	}
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing version catalog: %w", err)
	}

	catalog := &Catalog{}
	for alias, value := range raw.Libraries {
		library := &CatalogLibrary{Alias: alias}
		var version any
		switch entry := value.(type) {
		case string:
			parts := strings.Split(entry, ":")
			if len(parts) < 2 {
				continue
			}
			library.Group, library.Name = parts[0], parts[1]
			if len(parts) > 2 {
				version = parts[2]
			}
		case map[string]any:
			library.Group, _ = entry["group"].(string) //nolint:errcheck // a missing key is an empty string
			library.Name, _ = entry["name"].(string)   //nolint:errcheck // as above
			if module, ok := entry["module"].(string); ok {
				library.Group, library.Name, _ = strings.Cut(module, ":")
			}
			version = entry["version"]
		}
		if library.Group == "" || library.Name == "" {
			continue
		}
		library.Version, library.Requested = catalogVersion(version, raw.Versions)
		catalog.Libraries = append(catalog.Libraries, library)
	}

	for alias, value := range raw.Plugins {
		plugin := &CatalogPlugin{Alias: alias}
		var version any
		switch entry := value.(type) {
		case string:
			var text string
			plugin.ID, text, _ = strings.Cut(entry, ":")
			if text != "" {
				version = text
			}
		case map[string]any:
			plugin.ID, _ = entry["id"].(string) //nolint:errcheck // a missing key is an empty string
			version = entry["version"]
		}
		if plugin.ID == "" {
			continue
		}
		plugin.Version, plugin.Requested = catalogVersion(version, raw.Versions)
		catalog.Plugins = append(catalog.Plugins, plugin)
	}

	sort.Slice(catalog.Libraries, func(i, j int) bool { return catalog.Libraries[i].Alias < catalog.Libraries[j].Alias })
	sort.Slice(catalog.Plugins, func(i, j int) bool { return catalog.Plugins[i].Alias < catalog.Plugins[j].Alias })
	return catalog, nil
}

// oneVersion matches a version that is one version: no range brackets,
// no "+" at its end for the newest, no "latest." selector.
var oneVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)

func isOneVersion(text string) bool {
	return oneVersion.MatchString(text) && !strings.HasPrefix(text, "latest.")
}

// catalogVersion reads a version as a catalog writes it, and returns the
// version it pins when it pins one, and what is asked for otherwise.
//
// A string is a required version; a reference names an entry of
// [versions], which is a string or a table; a table holds constraints,
// of which "strictly" and "require" name the version asked for and
// "prefer" only a preference among what they allow.
func catalogVersion(value any, versions map[string]any) (version, requested string) {
	switch v := value.(type) {
	case nil:
		return "", ""
	case string:
		if isOneVersion(v) {
			return v, ""
		}
		return "", v
	case map[string]any:
		if ref, ok := v["ref"].(string); ok {
			referenced, defined := versions[ref]
			if !defined {
				return "", "version.ref=" + ref
			}
			return catalogVersion(referenced, nil)
		}
		for _, constraint := range []string{"strictly", "require"} {
			if text, ok := v[constraint].(string); ok {
				if isOneVersion(text) {
					return text, ""
				}
				return "", constraint + " " + text
			}
		}
		if text, ok := v["prefer"].(string); ok {
			return "", "prefer " + text
		}
	}
	return "", ""
}

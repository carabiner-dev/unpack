// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"bufio"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file works out which registry a project fetches its packages from,
// for the locks that do not say: pnpm's and Yarn berry's record what was
// resolved and leave where from to the configuration, .npmrc and
// .yarnrc.yml. It matters because only the public registry is asked about
// packages, and a package of a private one must not be named to it.
//
// What is read is the project's own configuration, the user's, and the
// environment. That is not all there is: a registry can also be given on
// a command line, or set on the machine the lock was made on and not on
// this one. So the answer is only ever "public as far as can be told",
// and anything that cannot be read settles it the cautious way.

// registryConfig says which registry a project's packages come from.
type registryConfig struct {
	// defaultRegistry is the registry packages are fetched from, empty
	// for the public one.
	defaultRegistry string

	// scoped maps a scope, "@acme", to the registry its packages are
	// fetched from instead.
	scoped map[string]string

	// undecided is set when a configuration is there and cannot be made
	// sense of. Nothing is then taken for public.
	undecided bool
}

// public says whether a package is fetched from the public registry, as
// far as the configuration tells.
func (rc *registryConfig) public(name string) bool {
	if rc.undecided {
		return false
	}
	registry := rc.defaultRegistry
	if scope, _, scopedName := strings.Cut(name, "/"); scopedName && strings.HasPrefix(scope, "@") {
		if scopeRegistry, ok := rc.scoped[strings.ToLower(scope)]; ok {
			registry = scopeRegistry
		}
	}
	return registry == "" || isPublicRegistryURL(registry)
}

// setDefault and setScope record a registry, from whichever file or
// variable states it. A value still holding a variable to expand could be
// anything.
func (rc *registryConfig) setDefault(registry string) {
	if registry = rc.checked(registry); registry != "" {
		rc.defaultRegistry = registry
	}
}

func (rc *registryConfig) setScope(scope, registry string) {
	if registry = rc.checked(registry); registry == "" {
		return
	}
	if rc.scoped == nil {
		rc.scoped = map[string]string{}
	}
	if !strings.HasPrefix(scope, "@") {
		scope = "@" + scope
	}
	rc.scoped[strings.ToLower(scope)] = registry
}

func (rc *registryConfig) checked(registry string) string {
	registry = strings.Trim(strings.TrimSpace(registry), `"'`)
	if strings.Contains(registry, "${") {
		rc.undecided = true
		return ""
	}
	return registry
}

// isPublicRegistryURL says whether a URL is on the public npm registry.
func isPublicRegistryURL(raw string) bool {
	location, err := url.Parse(raw)
	if err != nil || location.Scheme != "https" {
		return false
	}
	_, public := publicRegistryHosts[location.Hostname()]
	return public
}

// readNpmrc applies the registries an .npmrc states. The file not being
// there says nothing; one that is there and cannot be read leaves the
// question open.
func (rc *registryConfig) readNpmrc(path string) {
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			rc.undecided = true
		}
		return
	}
	defer f.Close() //nolint:errcheck // read-only

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		switch {
		case key == "registry":
			rc.setDefault(value)
		case strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry"):
			rc.setScope(strings.TrimSuffix(key, ":registry"), value)
		}
	}
	if scanner.Err() != nil {
		rc.undecided = true
	}
}

// readYAML reads a YAML configuration file into a map. found is false
// when the file is not there.
func (rc *registryConfig) readYAML(path string) (doc map[string]any, found bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			rc.undecided = true
		}
		return nil, false
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		rc.undecided = true
		return nil, false
	}
	return doc, true
}

// readPnpmWorkspace applies the registries a pnpm-workspace.yaml states,
// where pnpm also takes its settings from.
func (rc *registryConfig) readPnpmWorkspace(path string) {
	doc, found := rc.readYAML(path)
	if !found {
		return
	}
	if registry, ok := doc["registry"].(string); ok {
		rc.setDefault(registry)
	}
	if registries, ok := doc["registries"].(map[string]any); ok {
		for name, value := range registries {
			registry, ok := value.(string)
			if !ok {
				continue
			}
			if name == "default" {
				rc.setDefault(registry)
			} else {
				rc.setScope(name, registry)
			}
		}
	}
}

// readYarnrc applies the registries a .yarnrc.yml states.
func (rc *registryConfig) readYarnrc(path string) {
	doc, found := rc.readYAML(path)
	if !found {
		return
	}
	if registry, ok := doc["npmRegistryServer"].(string); ok {
		rc.setDefault(registry)
	}
	if scopes, ok := doc["npmScopes"].(map[string]any); ok {
		for scope, value := range scopes {
			settings, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if registry, ok := settings["npmRegistryServer"].(string); ok {
				rc.setScope(scope, registry)
			}
		}
	}
}

// userConfigPath is a file of the given name in the user's home, or
// empty when there is no telling where that is.
func userConfigPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, name)
}

// pnpmRegistryConfig reads where a pnpm project fetches packages from:
// the user's .npmrc, then the project's, then its pnpm-workspace.yaml,
// then the environment, each overriding the one before as pnpm has them.
func pnpmRegistryConfig(workDir string) *registryConfig {
	rc := &registryConfig{}
	if user := userConfigPath(".npmrc"); user != "" {
		rc.readNpmrc(user)
	}
	rc.readNpmrc(filepath.Join(workDir, ".npmrc"))
	rc.readPnpmWorkspace(filepath.Join(workDir, "pnpm-workspace.yaml"))
	for _, variable := range []string{"npm_config_registry", "NPM_CONFIG_REGISTRY"} {
		if registry := os.Getenv(variable); registry != "" {
			rc.setDefault(registry)
		}
	}
	return rc
}

// yarnRegistryConfig reads where a Yarn berry project fetches packages
// from: the user's .yarnrc.yml, then the project's, then the environment.
func yarnRegistryConfig(workDir string) *registryConfig {
	rc := &registryConfig{}
	if user := userConfigPath(".yarnrc.yml"); user != "" {
		rc.readYarnrc(user)
	}
	rc.readYarnrc(filepath.Join(workDir, ".yarnrc.yml"))
	if registry := os.Getenv("YARN_NPM_REGISTRY_SERVER"); registry != "" {
		rc.setDefault(registry)
	}
	return rc
}

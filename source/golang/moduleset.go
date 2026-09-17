// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"fmt"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/mod/modfile"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// Module identifies one Go module at one version. Sums carries the module's
// checksums the way go.sum and Go binaries record them, "h1:" prefixed.
type Module struct {
	Path    string
	Version string
	Sums    []string
}

// Key returns the module in the module@version form the graph is keyed by.
func (m Module) Key() string { return m.Path + "@" + m.Version }

// Replacement is the target of a replace directive: the module path and
// version that stand in for the replaced module. An empty Path keeps the
// original path and replaces the version alone.
type Replacement struct {
	Path    string
	Version string
}

// ModuleSet is the input to the Go graph builder: a program's main module and
// the modules built into it. A go.mod/go.sum pair reduces to one, and so does
// the build info embedded in a Go binary, which is what lets the same builder
// render both.
//
// Edges among Modules are resolved from each module's own go.mod (see
// resolveGraph). A module that no edge reaches, not even from the root, is
// not emitted; list every module a flat inventory must show under Requires.
type ModuleSet struct {
	// Main is the module the graph is rooted at. Only its path is read.
	Main Module

	// GoVersion is the Go release the program targets, without the "go"
	// prefix ("1.24.0"). When set, the root gets a stdlib dependency at
	// that version.
	GoVersion string

	// Requires lists the modules the main module requires. Each becomes
	// an edge from the root.
	Requires []Module

	// Modules lists every module in the build, Requires included. This is
	// the set edges are resolved within: a requirement of one of these
	// modules only becomes an edge when its target is also in the set.
	Modules []Module

	// Replaces maps a module path, or a module@version, to its replacement.
	// It is consulted when matching a module's requirements against the
	// set, so replaced paths resolve to the module actually built.
	Replaces map[string]Replacement
}

// sumHashes indexes the set's checksums by module key, the shape the node
// converter reads them in.
func (s *ModuleSet) sumHashes() map[string][]string {
	hashes := make(map[string][]string, len(s.Modules))
	for _, m := range s.Modules {
		hashes[m.Key()] = m.Sums
	}
	return hashes
}

// BuildNodeList renders a module set as a protobom NodeList: a root node for
// the main module, the stdlib at the set's Go version, one node per module
// reached through the graph with its checksums, and typed edges between
// them. Edges come from each module's go.mod, read from the local module
// cache and, when the networking level allows, from the module proxy; with
// networking enabled, dependency nodes are also enriched with license and
// source repository data.
func (d *Decomposer) BuildNodeList(set *ModuleSet, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if set == nil || set.Main.Path == "" {
		return nil, fmt.Errorf("module set has no main module")
	}
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}
	dOpts := d.getOptions(opts)

	trees := d.resolveGraph(set, dOpts, opts.Networking)

	nl, err := d.convertTrees(opts, set.Main.Path, &trees, set.GoVersion, set.sumHashes())
	if err != nil {
		return nil, fmt.Errorf("converting graph trees: %w", err)
	}

	if opts.Networking >= api.NetworkEssential {
		d.enrichLicenses(nl, set.Main.Path, dOpts, opts.Networking)
	}
	return nl, nil
}

// resolveGraph builds the adjacency map of a module set. The root's edges
// are the set's Requires; every other edge is read from the requiring
// module's go.mod and kept only when its target is in the set.
func (d *Decomposer) resolveGraph(set *ModuleSet, opts *Options, networking api.NetworkLevel) map[string][]string {
	trees := make(map[string][]string)

	resolved := make(map[string]bool, len(set.Modules))
	for _, m := range set.Modules {
		resolved[m.Key()] = false
	}

	rootKey := set.Main.Path
	for _, m := range set.Requires {
		resolved[m.Key()] = true
		trees[rootKey] = append(trees[rootKey], m.Key())
	}

	d.fetchDependencyGraph(trees, resolved, set.Replaces, opts, networking)
	return trees
}

// moduleSetFromGoMod reduces a parsed go.mod and the go.sum beside it to a
// module set: the requirements with replace directives applied and excludes
// dropped, plus every module go.sum knows about, which is how transitive
// modules enter the set. A missing or unreadable go.sum leaves the set with
// the requirements alone.
func (d *Decomposer) moduleSetFromGoMod(root *modfile.File, goModPath string) *ModuleSet {
	set := &ModuleSet{
		Main:     Module{Path: root.Module.Mod.Path},
		Replaces: make(map[string]Replacement),
	}
	if root.Go != nil {
		set.GoVersion = root.Go.Version
	}

	for _, r := range root.Replace {
		if r.New.Path == "" || isLocalReplace(r.New.Path) {
			continue
		}
		repl := Replacement{Path: r.New.Path, Version: r.New.Version}
		set.Replaces[r.Old.Path] = repl
		if r.Old.Version != "" {
			set.Replaces[r.Old.Path+"@"+r.Old.Version] = repl
		}
	}

	excludes := make(map[string]struct{}, len(root.Exclude))
	for _, e := range root.Exclude {
		excludes[e.Mod.Path+"@"+e.Mod.Version] = struct{}{}
	}

	// go.sum is read first so the requirements carry their checksums. Its
	// absence is not an error: the graph is just built without hashes and
	// without the transitive modules it would have listed.
	goSumPath := strings.TrimSuffix(goModPath, ".mod") + ".sum"
	sums, err := d.parseGoSum(goSumPath)
	if err != nil {
		sums = nil
	}

	seen := make(map[string]struct{})
	for _, req := range root.Require {
		modPath, version := d.resolveModule(req.Mod.Path, req.Mod.Version, set.Replaces)
		m := Module{Path: modPath, Version: version}
		if _, excluded := excludes[m.Key()]; excluded {
			continue
		}
		m.Sums = sums[m.Key()]
		set.Requires = append(set.Requires, m)
		if _, dup := seen[m.Key()]; !dup {
			seen[m.Key()] = struct{}{}
			set.Modules = append(set.Modules, m)
		}
	}

	// Sorted for a deterministic module order.
	keys := make([]string, 0, len(sums))
	for key := range sums {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, dup := seen[key]; dup {
			continue
		}
		if _, excluded := excludes[key]; excluded {
			continue
		}
		modPath, version, ok := strings.Cut(key, "@")
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		set.Modules = append(set.Modules, Module{Path: modPath, Version: version, Sums: sums[key]})
	}

	return set
}

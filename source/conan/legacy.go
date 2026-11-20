// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package conan

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/protobom/protobom/pkg/sbom"
)

// This file reads the lockfiles of Conan 1, which are another document
// than Conan 2's and hold more: the dependency graph itself. Each node is
// a package, or the project the lockfile was made for, and lists the
// nodes it requires, so which package requires which is known and the
// graph need not be flat.
//
// Conan 1 called the format experimental and changed it between
// releases. What is read is the shape of its last ones, version 0.4.

// ErrLegacyGraph is returned for a Conan 1 lockfile whose graph cannot be
// made out: a shape of an older release, or a lock bundle.
var ErrLegacyGraph = errors.New("the graph of the Conan 1 lockfile cannot be made out")

// LegacyLock is a Conan 1 lockfile.
type LegacyLock struct {
	Version string
	Nodes   map[string]*LegacyNode
}

// LegacyNode is one node of the graph of a Conan 1 lockfile.
type LegacyNode struct {
	ID string

	// Ref names the package. The project a lockfile was made for has
	// none when it is a conanfile.txt, and a path in either case.
	Ref  *Reference
	Path string

	// Context is "host" for what is built for the target and "build"
	// for what runs on the build machine.
	Context string

	PackageID       string
	PackageRevision string

	// Requires and BuildRequires are the ids of the nodes this one
	// requires.
	Requires      []string
	BuildRequires []string

	// PythonRequires are the packages its recipe is written with, which
	// are no nodes of the graph.
	PythonRequires []*Reference
}

type rawLegacyLock struct {
	Version   string `json:"version"`
	GraphLock struct {
		Nodes map[string]*struct {
			Ref            string   `json:"ref"`
			Path           string   `json:"path"`
			Context        string   `json:"context"`
			PackageID      string   `json:"package_id"`
			Prev           string   `json:"prev"`
			Requires       []string `json:"requires"`
			BuildRequires  []string `json:"build_requires"`
			PythonRequires []string `json:"python_requires"`
		} `json:"nodes"`
	} `json:"graph_lock"`
}

// noRevision is what Conan 1 wrote for a package revision when revisions
// were not in use.
const noRevision = "0"

// ParseLegacyLock reads the contents of a Conan 1 lockfile.
func ParseLegacyLock(data []byte) (*LegacyLock, error) {
	raw := &rawLegacyLock{}
	if err := json.Unmarshal(data, raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLegacyGraph, err)
	}
	if len(raw.GraphLock.Nodes) == 0 {
		return nil, fmt.Errorf("%w: it has no nodes", ErrLegacyGraph)
	}

	lock := &LegacyLock{Version: raw.Version, Nodes: map[string]*LegacyNode{}}
	for id, rawNode := range raw.GraphLock.Nodes {
		if rawNode == nil {
			return nil, fmt.Errorf("%w: node %s is empty", ErrLegacyGraph, id)
		}
		node := &LegacyNode{
			ID: id, Path: rawNode.Path, Context: rawNode.Context,
			PackageID: rawNode.PackageID, Requires: rawNode.Requires, BuildRequires: rawNode.BuildRequires,
		}
		if rawNode.Prev != noRevision {
			node.PackageRevision = rawNode.Prev
		}
		if rawNode.Ref != "" {
			ref, err := ParseReference(rawNode.Ref)
			if err != nil {
				return nil, fmt.Errorf("%w: node %s: %w", ErrLegacyGraph, id, err)
			}
			node.Ref = ref
		}
		for _, entry := range rawNode.PythonRequires {
			ref, err := ParseReference(entry)
			if err != nil {
				return nil, fmt.Errorf("%w: node %s: %w", ErrLegacyGraph, id, err)
			}
			node.PythonRequires = append(node.PythonRequires, ref)
		}
		lock.Nodes[id] = node
	}

	for id, node := range lock.Nodes {
		for _, required := range slices.Concat(node.Requires, node.BuildRequires) {
			if _, ok := lock.Nodes[required]; !ok {
				return nil, fmt.Errorf("%w: node %s requires node %s, which is not there", ErrLegacyGraph, id, required)
			}
		}
	}
	if _, err := lock.Root(); err != nil {
		return nil, err
	}
	return lock, nil
}

// Root returns the node the lockfile was made for: the one no other
// requires, as Conan itself finds it. Its id is not fixed.
func (l *LegacyLock) Root() (*LegacyNode, error) {
	required := map[string]bool{}
	for _, node := range l.Nodes {
		for _, id := range slices.Concat(node.Requires, node.BuildRequires) {
			required[id] = true
		}
	}
	roots := []string{}
	for id := range l.Nodes {
		if !required[id] {
			roots = append(roots, id)
		}
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("%w: %d nodes are required by no other, where there is to be one", ErrLegacyGraph, len(roots))
	}
	return l.Nodes[roots[0]], nil
}

// legacyBuilder renders the graph of a Conan 1 lockfile.
type legacyBuilder struct {
	*builder
	lock     *LegacyLock
	purposes map[string]sbom.Edge_Type

	// nodes are the rendered packages by reference: a package the graph
	// holds once for the target and once for the build machine is one
	// package.
	nodes   map[string]*sbom.Node
	visited map[string]bool
}

// build walks the graph from the node the lockfile was made for.
func (lb *legacyBuilder) build() error {
	root, err := lb.lock.Root()
	if err != nil {
		return err
	}
	lb.visited[root.ID] = true
	return lb.walk(root, lb.root, true)
}

// walk relates what a node requires to the package rendered for it.
func (lb *legacyBuilder) walk(node *LegacyNode, parent *sbom.Node, fromRoot bool) error {
	for _, list := range []struct {
		ids  []string
		edge sbom.Edge_Type
	}{
		{node.Requires, sbom.Edge_dependsOn},
		{node.BuildRequires, sbom.Edge_buildDependency},
	} {
		for _, id := range sortedIDs(list.ids) {
			child := lb.lock.Nodes[id]
			if child.Ref == nil {
				continue
			}
			edge := list.edge
			// The manifest says what the project's own requirements
			// are for; a lockfile lists what its tests need with the
			// rest.
			if purpose, ok := lb.purposes[child.Ref.Name]; ok && fromRoot {
				edge = purpose
			}
			rendered, err := lb.relate(child.Ref, child, parent, edge)
			if err != nil {
				return err
			}
			if rendered == nil || lb.visited[id] {
				continue
			}
			lb.visited[id] = true
			if err := lb.walk(child, rendered, false); err != nil {
				return err
			}
		}
	}

	for _, ref := range node.PythonRequires {
		if _, err := lb.relate(ref, nil, parent, sbom.Edge_buildDependency); err != nil {
			return err
		}
	}
	return nil
}

// relate adds an edge to a package, rendering it first when it is new. It
// returns nothing for a package the options leave out, and what is only
// reached through it is left out with it.
func (lb *legacyBuilder) relate(ref *Reference, node *LegacyNode, parent *sbom.Node, edge sbom.Edge_Type) (*sbom.Node, error) {
	if edge == sbom.Edge_devDependency && !lb.opts.IncludeDev {
		return nil, nil
	}
	if edge == sbom.Edge_buildDependency && !lb.opts.IncludeBuild {
		return nil, nil
	}

	key := ref.Name + "/" + ref.Version + "@" + ref.User + "/" + ref.Channel + "#" + ref.Revision
	rendered, known := lb.nodes[key]
	if !known {
		if node != nil && node.PackageID != "" {
			ref = &Reference{
				Name: ref.Name, Version: ref.Version, User: ref.User, Channel: ref.Channel, Revision: ref.Revision,
				Packages: map[string]string{node.PackageID: node.PackageRevision},
			}
		}
		rendered = packageNode(ref)
		lb.nodes[key] = rendered
		lb.nl.AddNode(rendered)
	}
	if rendered.GetId() == parent.GetId() {
		return rendered, nil
	}
	if err := lb.nl.RelateNodeAtID(rendered, parent.GetId(), edge); err != nil {
		return nil, fmt.Errorf("relating %s: %w", ref.Name, err)
	}
	return rendered, nil
}

// sortedIDs orders node ids as numbers, which is what they are, so the
// graph is walked the same way on every run.
func sortedIDs(ids []string) []string {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b string) int {
		na, errA := strconv.Atoi(a)
		nb, errB := strconv.Atoi(b)
		if errA != nil || errB != nil || na == nb {
			switch {
			case a < b:
				return -1
			case a > b:
				return 1
			}
			return 0
		}
		return na - nb
	})
	return sorted
}

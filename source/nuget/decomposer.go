// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package nuget reads the dependencies of .NET projects from the lockfile
// NuGet writes, packages.lock.json.
package nuget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var (
	_ api.Decomposer        = (*Decomposer)(nil)
	_ api.SourceDecomposer  = (*Decomposer)(nil)
	_ api.ContextDecomposer = (*Decomposer)(nil)
	_ api.ContextReporter   = (*Decomposer)(nil)
)

// Properties a dependency node carries.
const (
	// PropertyType is how the project comes to have the package: Direct,
	// Transitive, CentralTransitive or Project.
	PropertyType = "nuget:type"

	// PropertyTarget is a target the package is resolved for, once for
	// each: a framework, or a framework and a runtime ("net8.0/win-x64").
	PropertyTarget = "nuget:target"

	// PropertyRequested is the range of versions asked for.
	PropertyRequested = "nuget:requested"

	// PropertyContentHash is the hash NuGet records for the package, a
	// SHA-512 in base64.
	//
	// It is not the hash of the file a feed serves. Packages on
	// nuget.org are signed, and NuGet hashes a package's content
	// without its signature, so that the hash stays what it was when a
	// signature is added. Hashing the .nupkg one downloads gives another
	// value, which is why this is a property and not one of the node's
	// hashes: it can only be checked by NuGet, or against another
	// lockfile.
	PropertyContentHash = "nuget:content-hash"
)

// Project files, one of which names the project a lockfile is of.
var projectSuffixes = []string{".csproj", ".fsproj", ".vbproj"}

// New returns a ready-to-use NuGet decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from .NET projects.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the lockfile is read in Go.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the lockfile, as it stands in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

// FindCodeBases locates .NET projects by their lockfile, which is beside
// the project file. A project restored without one is not found.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations(LockFile)
}

// Extract is ExtractWithContext with a background context, for a caller
// that has none to give.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractWithContext(context.Background(), opts)
}

// ExtractWithContext reads the lockfile and builds the graph it holds.
//
// A lockfile resolves the project once for each target it is built for,
// and the resolutions may differ: a package needed on one framework and
// not another, or at another version. The graph is their union. A
// package at a version is one node however many targets have it, each
// named on it, and a package two targets resolve to two versions is two
// nodes.
func (d *Decomposer) ExtractWithContext(_ context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	lock, err := ReadLock(filepath.Join(workDir, LockFile))
	if err != nil {
		return nil, err
	}

	b := &builder{nl: sbom.NewNodeList(), lock: lock, nodes: map[string]*sbom.Node{}, edges: map[string]bool{}}
	b.root = rootNode(workDir, opts)
	b.nl.AddRootNode(b.root)
	for _, target := range lock.Targets {
		if err := b.addTarget(target); err != nil {
			return nil, err
		}
	}
	return b.nl, nil
}

type builder struct {
	nl    *sbom.NodeList
	lock  *Lock
	root  *sbom.Node
	nodes map[string]*sbom.Node
	edges map[string]bool
}

// addTarget adds the resolution of one target to the graph.
func (b *builder) addTarget(target *Target) error {
	reached := map[*Entry]bool{}

	// What the project references itself: packages, and other projects
	// of the solution.
	for _, entry := range target.Entries {
		if entry.Type != TypeDirect && entry.Type != TypeProject {
			continue
		}
		if err := b.walk(target, entry, b.root, reached); err != nil {
			return err
		}
	}
	// A transitive package nothing above leads to is still resolved for
	// the target, and hangs from the project so that it is not lost: a
	// package pinned centrally that no reference requires, or one whose
	// parent is in another target.
	for _, entry := range target.Entries {
		if reached[entry] {
			continue
		}
		if err := b.walk(target, entry, b.root, reached); err != nil {
			return err
		}
	}
	return nil
}

// walk relates an entry to what requires it, and on its first visit in
// the target goes on to what it depends on.
func (b *builder) walk(target *Target, entry *Entry, parent *sbom.Node, reached map[*Entry]bool) error {
	node := b.node(target, entry)
	if err := b.relate(parent, node); err != nil {
		return err
	}
	if reached[entry] {
		return nil
	}
	reached[entry] = true

	for _, dep := range entry.Dependencies {
		child, owner := b.resolve(target, dep.ID)
		if child == nil {
			// Not locked for the target: a reference assembly of the
			// framework, which no package provides.
			continue
		}
		if owner != target {
			// The framework's own resolution has it, and has walked
			// it or will: only the edge is this target's to add.
			if err := b.relate(node, b.node(owner, child)); err != nil {
				return err
			}
			continue
		}
		if err := b.walk(target, child, node, reached); err != nil {
			return err
		}
	}
	return nil
}

// resolve finds what an id is locked to for a target, and the target
// whose resolution has it. The resolution for a runtime only lists what
// differs from the framework's own, so an id it does not have is looked
// up there.
func (b *builder) resolve(target *Target, id string) (*Entry, *Target) {
	if entry := target.Find(id); entry != nil {
		return entry, target
	}
	if target.Runtime == "" {
		return nil, nil
	}
	base, _, _ := strings.Cut(target.Name, "/")
	for _, other := range b.lock.Targets {
		if other.Name == base {
			if entry := other.Find(id); entry != nil {
				return entry, other
			}
		}
	}
	return nil, nil
}

// node returns the node of an entry, rendering it on its first sight and
// adding to it what this target says of it.
func (b *builder) node(target *Target, entry *Entry) *sbom.Node {
	key := strings.ToLower(entry.ID) + "@" + entry.Resolved
	node, known := b.nodes[key]
	if !known {
		node = &sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    entry.ID,
			Version: entry.Resolved,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): entryPurl(entry),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		b.nodes[key] = node
		b.nl.AddNode(node)
	}
	addProperty(node, PropertyType, entry.Type)
	addProperty(node, PropertyRequested, entry.Requested)
	addProperty(node, PropertyContentHash, entry.ContentHash)
	addProperty(node, PropertyTarget, target.Name)
	return node
}

// entryPurl names an entry: a package as pkg:nuget, by the id the
// lockfile writes, and a project of the solution, which is no package of
// any feed, as pkg:generic.
func entryPurl(entry *Entry) string {
	if entry.Type == TypeProject {
		return purl.NewPackageURL(purl.TypeGeneric, "", entry.ID, "", nil, "").ToString()
	}
	return purl.NewPackageURL(purl.TypeNuget, "", entry.ID, entry.Resolved, nil, "").ToString()
}

// relate adds an edge, once.
func (b *builder) relate(from, to *sbom.Node) error {
	key := from.GetId() + ">" + to.GetId()
	if from.GetId() == to.GetId() || b.edges[key] {
		return nil
	}
	b.edges[key] = true
	if err := b.nl.RelateNodeAtID(to, from.GetId(), sbom.Edge_dependsOn); err != nil {
		return fmt.Errorf("relating %s: %w", to.GetName(), err)
	}
	return nil
}

// addProperty adds a property to a node, once for a name and value.
func addProperty(node *sbom.Node, name, value string) {
	if value == "" {
		return
	}
	for _, property := range node.GetProperties() {
		if property.GetName() == name && property.GetData() == value {
			return
		}
	}
	node.Properties = append(node.Properties, &sbom.Property{Name: name, Data: value})
}

// projectName names the project a lockfile is of: the project file
// beside it when there is one and only one, and the directory otherwise.
func projectName(workDir string) string {
	names := []string{}
	if entries, err := os.ReadDir(workDir); err == nil {
		for _, entry := range entries {
			for _, suffix := range projectSuffixes {
				if name, ok := strings.CutSuffix(entry.Name(), suffix); ok && name != "" && !entry.IsDir() {
					names = append(names, name)
				}
			}
		}
	}
	if len(names) == 1 {
		return names[0]
	}
	abs, err := filepath.Abs(workDir)
	if err != nil {
		abs = workDir
	}
	return filepath.Base(abs)
}

func rootNode(workDir string, opts *api.DecomposerOptions) *sbom.Node {
	name := projectName(workDir)
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: opts.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeNuget, "", name, opts.Version, nil, "").ToString(),
		},
	}
	if opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

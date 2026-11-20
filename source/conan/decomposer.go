// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package conan reads the dependencies of C and C++ projects managed with
// the Conan package manager, from the lockfile Conan writes and the
// declarative manifest beside it.
package conan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
	"github.com/carabiner-dev/unpack/internal/logging"
)

var (
	_ api.Decomposer        = (*Decomposer)(nil)
	_ api.SourceDecomposer  = (*Decomposer)(nil)
	_ api.ContextDecomposer = (*Decomposer)(nil)
	_ api.ContextReporter   = (*Decomposer)(nil)
)

// Properties a dependency node carries.
const (
	// PropertyRevision is the recipe revision the lock pins: a hash of
	// the recipe that builds the package, not of its sources or
	// binaries, which is why it is not among the node's hashes.
	PropertyRevision = "conan:recipe-revision"

	// PropertyPackageID is the id of a binary the lock pins for the
	// package, and PropertyPackageRevision that binary's revision, as
	// id#revision. A lockfile only has them when made to lock binaries.
	PropertyPackageID       = "conan:package-id"
	PropertyPackageRevision = "conan:package-revision"

	// PropertyRange is the version range a manifest asks for, on a node
	// no lockfile gave a version.
	PropertyRange = "conan:version-range"
)

// New returns a ready-to-use Conan decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from Conan projects.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the files are read in Go, Conan is not run.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the lockfile and manifest, as they stand in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

// FindCodeBases locates Conan projects by their lockfile or their
// declarative manifest. A project that has only a conanfile.py and no
// lockfile is not found: its requirements are in a Python program.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	found := []string{}
	for _, name := range []string{LockFile, ManifestFile} {
		locations, err := index.FindFileLocations(name)
		if err != nil {
			return nil, err
		}
		for _, loc := range locations {
			if !slices.Contains(found, loc) {
				found = append(found, loc)
			}
		}
	}
	slices.Sort(found)
	return found, nil
}

// Extract is ExtractWithContext with a background context, for a caller
// that has none to give.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractWithContext(context.Background(), opts)
}

// ExtractWithContext reads the project's lockfile and manifest and
// returns the packages they name.
//
// From a Conan 2 lockfile the graph is flat: it lists the packages a
// graph resolved to and not the edges between them, so which package
// requires which is not known, nor which of them the project asks for
// itself. A Conan 1 lockfile holds the graph, and it is rendered as it
// is.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	log := logging.FromContext(ctx)

	lock, legacy, err := readLocks(filepath.Join(workDir, LockFile))
	switch {
	case errors.Is(err, ErrLegacyGraph):
		// A lockfile nobody can read locks nothing, which is no reason
		// to refuse the project: what its manifest asks for stands.
		log.Warn("conan: the lockfile is in a Conan 1 format that is not read, it is left aside",
			"lockfile", filepath.Join(workDir, LockFile), "error", err)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	locked := lock != nil || legacy != nil

	manifest, err := ReadManifest(filepath.Join(workDir, ManifestFile))
	switch {
	case errors.Is(err, fs.ErrNotExist) && !locked && !pathExists(filepath.Join(workDir, LockFile)):
		return nil, fmt.Errorf("no %s or %s in %s", LockFile, ManifestFile, workDir)
	case errors.Is(err, fs.ErrNotExist):
		manifest = &Manifest{}
	case err != nil:
		return nil, err
	}

	if !locked {
		log.Debug("conan: no lockfile read, the graph holds only what conanfile.txt asks for, at the versions or ranges it states",
			"manifest", filepath.Join(workDir, ManifestFile))
	}

	b := &builder{nl: sbom.NewNodeList(), opts: opts, seen: map[string]bool{}}
	b.root = rootNode(workDir, opts)
	b.nl.AddRootNode(b.root)

	// What the manifest says a package is for, where the lock only has
	// its list to go by: a lockfile lists what the tests need with what
	// the project is built from, as both are built for the same machine.
	purposes := map[string]sbom.Edge_Type{}
	for _, ref := range manifest.ToolRequires {
		purposes[ref.Name] = sbom.Edge_buildDependency
	}
	for _, ref := range manifest.TestRequires {
		purposes[ref.Name] = sbom.Edge_devDependency
	}

	if legacy != nil {
		lb := &legacyBuilder{
			builder: b, lock: legacy, purposes: purposes,
			nodes: map[string]*sbom.Node{}, visited: map[string]bool{},
		}
		if err := lb.build(); err != nil {
			return nil, err
		}
		return b.nl, nil
	}

	type list struct {
		refs []*Reference
		edge sbom.Edge_Type
	}
	lists := []list{
		{manifest.Requires, sbom.Edge_dependsOn},
		{manifest.ToolRequires, sbom.Edge_buildDependency},
		{manifest.TestRequires, sbom.Edge_devDependency},
	}
	if lock != nil {
		lists = []list{
			{lock.Requires, sbom.Edge_dependsOn},
			{lock.BuildRequires, sbom.Edge_buildDependency},
			{lock.PythonRequires, sbom.Edge_buildDependency},
			{lock.ConfigRequires, sbom.Edge_buildDependency},
		}
	}
	for _, l := range lists {
		for _, ref := range l.refs {
			edge := l.edge
			if purpose, ok := purposes[ref.Name]; ok && lock != nil {
				edge = purpose
			}
			if err := b.add(ref, edge); err != nil {
				return nil, err
			}
		}
	}
	return b.nl, nil
}

// readLocks reads the lockfile at a path, in whichever of Conan's two
// formats it is.
func readLocks(path string) (*Lock, *LegacyLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading lockfile: %w", err)
	}
	lock, err := ParseLock(data)
	switch {
	case err == nil:
		return lock, nil, nil
	case !errors.Is(err, ErrLegacyLockfile):
		return nil, nil, err
	}
	legacy, err := ParseLegacyLock(data)
	if err != nil {
		return nil, nil, err
	}
	return nil, legacy, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type builder struct {
	nl   *sbom.NodeList
	root *sbom.Node
	opts *api.DecomposerOptions
	seen map[string]bool
}

// add relates a package to the root, once. A lockfile may list several
// revisions of one version, newest first, and the first is kept.
func (b *builder) add(ref *Reference, edge sbom.Edge_Type) error {
	if edge == sbom.Edge_devDependency && !b.opts.IncludeDev {
		return nil
	}
	if edge == sbom.Edge_buildDependency && !b.opts.IncludeBuild {
		return nil
	}
	key := ref.Name + "/" + ref.Version + "@" + ref.User + "/" + ref.Channel
	if b.seen[key] {
		return nil
	}
	b.seen[key] = true

	if err := b.nl.RelateNodeAtID(packageNode(ref), b.root.GetId(), edge); err != nil {
		return fmt.Errorf("relating %s: %w", ref.Name, err)
	}
	return nil
}

func rootNode(workDir string, opts *api.DecomposerOptions) *sbom.Node {
	name := filepath.Base(workDir)
	if abs, err := filepath.Abs(workDir); err == nil {
		name = filepath.Base(abs)
	}
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: opts.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeGeneric, "", name, opts.Version, nil, "").ToString(),
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

// packageNode renders a reference. Its purl is of the conan type, with
// the user, channel and recipe revision as the qualifiers the type
// defines for them.
func packageNode(ref *Reference) *sbom.Node {
	qualifiers := purl.Qualifiers{}
	for _, q := range []struct{ key, value string }{
		{"channel", ref.Channel}, {"rrev", ref.Revision}, {"user", ref.User},
	} {
		if q.value != "" {
			qualifiers = append(qualifiers, purl.Qualifier{Key: q.key, Value: q.value})
		}
	}

	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    ref.Name,
		Version: ref.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeConan, "", ref.Name, ref.Version, qualifiers, "").ToString(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	if ref.Revision != "" {
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertyRevision, Data: ref.Revision})
	}
	for _, id := range slices.Sorted(maps.Keys(ref.Packages)) {
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertyPackageID, Data: id})
		if revision := ref.Packages[id]; revision != "" {
			node.Properties = append(node.Properties, &sbom.Property{Name: PropertyPackageRevision, Data: id + "#" + revision})
		}
	}
	if ref.Range != "" {
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertyRange, Data: ref.Range})
	}
	return node
}

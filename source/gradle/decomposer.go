// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gradle reads the dependencies of projects built with Gradle,
// from the lockfiles Gradle writes when dependency locking is on, and the
// checksums of its dependency verification.
package gradle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/chainguard-dev/clog"
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
	// PropertyConfiguration is a configuration the module is locked in,
	// once for each.
	PropertyConfiguration = "gradle:configuration"

	// PropertyBuildscript marks a module of the build script's
	// classpath: a plugin of the build, or what one requires.
	PropertyBuildscript = "gradle:buildscript"

	// PropertyVerifiedFile is the file of the module the node's hashes
	// are of, as the verification metadata names it.
	PropertyVerifiedFile = "gradle:verified-file"
)

// New returns a ready-to-use Gradle decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from Gradle projects.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the files are read in Go, Gradle is not
// run.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the lockfiles, as they stand in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

// FindCodeBases locates Gradle projects by their lockfiles. Every
// project of a build has its own, beside its build file, so each project
// with one is a codebase. A build that does not lock its dependencies is
// not found: what it depends on is in its build scripts, which are
// programs.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	found := []string{}
	for _, name := range []string{LockFile, BuildscriptLockFile} {
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
	// A build with a version catalog: the catalog is in the build's
	// gradle directory, and the codebase is the build.
	for dir, files := range *index {
		if filepath.Base(filepath.Clean(dir)) != catalogDir || !slices.Contains(files, catalogName) {
			continue
		}
		if build := filepath.Dir(filepath.Clean(dir)); !slices.Contains(found, build) {
			found = append(found, build)
		}
	}
	slices.Sort(found)
	return found, nil
}

// The directory and the name of a version catalog (see CatalogFile).
const (
	catalogDir  = "gradle"
	catalogName = "libs.versions.toml"
)

// Extract is ExtractWithContext with a background context, for a caller
// that has none to give.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractWithContext(context.Background(), opts)
}

// ExtractWithContext reads the lockfiles of a project and returns the
// modules they lock, each a dependency of the project.
//
// The graph is flat: a lockfile lists the module versions a project's
// configurations resolved to, and not which module requires which.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	log := logging.FromContext(ctx)

	lock, err := ReadLock(filepath.Join(workDir, LockFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	buildscript, err := ReadLock(filepath.Join(workDir, BuildscriptLockFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if lock == nil && buildscript == nil {
		// A build that does not lock may still say, in its version
		// catalog, what it asks for.
		catalog, err := ReadCatalog(filepath.Join(workDir, filepath.FromSlash(CatalogFile)))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no %s, %s or %s in %s", LockFile, BuildscriptLockFile, CatalogFile, workDir)
		}
		if err != nil {
			return nil, err
		}
		log.Debug("gradle: no lockfile, the graph holds what the version catalog declares, at the versions it asks for",
			"codebase", workDir)
		return extractCatalog(catalog, workDir, opts, loadVerification(workDir, log))
	}

	verification := loadVerification(workDir, log)

	nl := sbom.NewNodeList()
	root := rootNode(workDir, opts)
	nl.AddRootNode(root)

	seen := map[string]bool{}
	relate := func(module *Module, edge sbom.Edge_Type, fromBuildscript bool) error {
		key := module.Group + ":" + module.Name + ":" + module.Version
		if seen[key] {
			return nil
		}
		if (edge == sbom.Edge_devDependency && !opts.IncludeDev) || (edge == sbom.Edge_buildDependency && !opts.IncludeBuild) {
			return nil
		}
		seen[key] = true
		node := moduleNode(module, verification, fromBuildscript)
		if err := nl.RelateNodeAtID(node, root.GetId(), edge); err != nil {
			return fmt.Errorf("relating %s: %w", key, err)
		}
		return nil
	}

	// The project's own configurations first: a module that is also on
	// the build script's classpath is what the project is built from
	// before it is what builds it.
	if lock != nil {
		for _, module := range lock.Modules {
			if err := relate(module, edgeFor(module.Role()), false); err != nil {
				return nil, err
			}
		}
	}
	if buildscript != nil {
		for _, module := range buildscript.Modules {
			if err := relate(module, sbom.Edge_buildDependency, true); err != nil {
				return nil, err
			}
		}
	}
	return nl, nil
}

// loadVerification reads the checksums of the build's dependency
// verification, when it has any. A file that cannot be read costs the
// hashes and not the inventory.
func loadVerification(workDir string, log *clog.Logger) *Verification {
	path := FindVerification(workDir)
	if path == "" {
		return nil
	}
	verification, err := ReadVerification(path)
	if err != nil {
		log.Warn("gradle: the verification metadata cannot be read, modules get no hashes", "file", path, "error", err)
		return nil
	}
	return verification
}

// Properties of a node read from a version catalog.
const (
	// PropertyReadFrom says a module was read from a version catalog,
	// when the build had no lockfile: it is declared and asked for at a
	// version, and not resolved.
	PropertyReadFrom = "gradle:read-from"

	// PropertyAlias is the alias the catalog gives a library or a
	// plugin, which is how build scripts ask for it.
	PropertyAlias = "gradle:catalog-alias"

	// PropertyRequested is what a catalog asks for when it is not one
	// version: a range, a preference, a reference it does not define.
	PropertyRequested = "gradle:requested"

	// PropertyPluginID is the id of a plugin. Its node is the plugin's
	// marker artifact, which is what Gradle resolves the id to.
	PropertyPluginID = "gradle:plugin-id"
)

// ReadFromCatalog is the value of PropertyReadFrom.
const ReadFromCatalog = "version-catalog"

// extractCatalog renders a version catalog: its libraries as
// dependencies of the build and its plugins as build dependencies.
//
// The graph is flat, and holds what the catalog declares: the build's
// scripts may use less, and a restore brings in more.
func extractCatalog(catalog *Catalog, workDir string, opts *api.DecomposerOptions, verification *Verification) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	root := rootNode(workDir, opts)
	nl.AddRootNode(root)

	seen := map[string]bool{}
	relate := func(module *Module, edge sbom.Edge_Type, alias, requested, pluginID string) error {
		key := module.Group + ":" + module.Name + ":" + module.Version + ":" + requested
		if seen[key] {
			return nil
		}
		seen[key] = true
		node := moduleNode(module, verification, false)
		if pluginID != "" {
			node.Name = pluginID
			node.PrimaryPurpose = nil
		}
		for _, property := range []struct{ name, value string }{
			{PropertyReadFrom, ReadFromCatalog},
			{PropertyAlias, alias},
			{PropertyRequested, requested},
			{PropertyPluginID, pluginID},
		} {
			if property.value != "" {
				node.Properties = append(node.Properties, &sbom.Property{Name: property.name, Data: property.value})
			}
		}
		if err := nl.RelateNodeAtID(node, root.GetId(), edge); err != nil {
			return fmt.Errorf("relating %s: %w", key, err)
		}
		return nil
	}

	for _, library := range catalog.Libraries {
		module := &Module{Group: library.Group, Name: library.Name, Version: library.Version}
		if err := relate(module, sbom.Edge_dependsOn, library.Alias, library.Requested, ""); err != nil {
			return nil, err
		}
	}
	if !opts.IncludeBuild {
		return nl, nil
	}
	for _, plugin := range catalog.Plugins {
		// Gradle resolves a plugin id to its marker artifact:
		// <id>:<id>.gradle.plugin:<version>.
		module := &Module{Group: plugin.ID, Name: plugin.ID + ".gradle.plugin", Version: plugin.Version}
		if err := relate(module, sbom.Edge_buildDependency, plugin.Alias, plugin.Requested, plugin.ID); err != nil {
			return nil, err
		}
	}
	return nl, nil
}

// edgeFor says how a module of a role relates to the project.
func edgeFor(role Role) sbom.Edge_Type {
	switch role {
	case RoleTest:
		return sbom.Edge_devDependency
	case RoleProcessor:
		return sbom.Edge_buildDependency
	case RoleCompileOnly:
		return sbom.Edge_providedDependency
	case RoleRuntime:
		return sbom.Edge_dependsOn
	}
	return sbom.Edge_dependsOn
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

// hashAlgorithms are the checksums verification metadata states, by the
// name of their element.
var hashAlgorithms = map[string]sbom.HashAlgorithm{
	"md5":    sbom.HashAlgorithm_MD5,
	"sha1":   sbom.HashAlgorithm_SHA1,
	"sha256": sbom.HashAlgorithm_SHA256,
	"sha512": sbom.HashAlgorithm_SHA512,
}

// moduleNode renders a locked module: a Maven coordinate, as Gradle's
// modules are, named as the Maven decomposer names them.
func moduleNode(module *Module, verification *Verification, fromBuildscript bool) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    module.Name,
		Version: module.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeMaven, module.Group, module.Name, module.Version, nil, "").ToString(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	for _, configuration := range module.Configurations {
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertyConfiguration, Data: configuration})
	}
	if fromBuildscript {
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertyBuildscript, Data: "true"})
	}

	if checksums, file := verification.Library(module); len(checksums) > 0 {
		node.Hashes = map[int32]string{}
		for name, value := range checksums {
			node.Hashes[int32(hashAlgorithms[name])] = value
		}
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertyVerifiedFile, Data: file})
	}
	return node
}

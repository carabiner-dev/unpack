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
	slices.Sort(found)
	return found, nil
}

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
		return nil, fmt.Errorf("no %s or %s in %s", LockFile, BuildscriptLockFile, workDir)
	}

	// The checksums of the build's dependency verification, when it has
	// any. A file that cannot be read costs the hashes and not the
	// inventory.
	var verification *Verification
	if path := FindVerification(workDir); path != "" {
		if verification, err = ReadVerification(path); err != nil {
			log.Warn("gradle: the verification metadata cannot be read, modules get no hashes", "file", path, "error", err)
		}
	}

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

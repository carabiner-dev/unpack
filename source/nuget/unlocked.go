// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/internal/logging"
)

// Properties of a node read without a lockfile.
const (
	// PropertyReadFrom says which file a package was read from when
	// there was no lockfile: project, for a project file's references,
	// or packages.config. A node with it was asked for and not
	// resolved.
	PropertyReadFrom = "nuget:read-from"

	// PropertyCondition is the condition a reference is under, most
	// often a target framework.
	PropertyCondition = "nuget:condition"
)

// Values of PropertyReadFrom.
const (
	ReadFromProject        = "project"
	ReadFromPackagesConfig = "packages.config"
)

// isProjectFile says whether a file name is a .NET project file's.
func isProjectFile(name string) bool {
	return slices.ContainsFunc(projectSuffixes, func(suffix string) bool {
		return strings.HasSuffix(name, suffix) && len(name) > len(suffix)
	})
}

// extractUnlocked reads a project that has no lockfile, from what it
// asks for: the package references of its project files, at the versions
// they or the repository's central file state, and its packages.config.
//
// The graph is flat and holds direct references only. What those
// packages bring in is decided by a restore and written nowhere in the
// source; packages.config is the exception, which lists everything
// installed, and still says nothing of what brought what.
func (d *Decomposer) extractUnlocked(ctx context.Context, workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	log := logging.FromContext(ctx)

	entries, err := os.ReadDir(workDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", workDir, err)
	}
	projectFiles := []string{}
	hasConfig := false
	for _, entry := range entries {
		switch {
		case entry.IsDir():
		case isProjectFile(entry.Name()):
			projectFiles = append(projectFiles, entry.Name())
		case entry.Name() == PackagesConfigFile:
			hasConfig = true
		}
	}
	if len(projectFiles) == 0 && !hasConfig {
		return nil, fmt.Errorf("no %s, project file or %s in %s", LockFile, PackagesConfigFile, workDir)
	}
	slices.Sort(projectFiles)
	log.Debug("nuget: no lockfile, the graph holds only the packages the project asks for, at the versions it states",
		"codebase", workDir)

	// What the repository states for the projects below a directory:
	// the versions it manages centrally, and shared properties.
	above := func(name string) *Project {
		file := findAbove(workDir, name)
		if file == "" {
			return &Project{Central: map[string]string{}, Properties: map[string]string{}}
		}
		project, err := ReadProject(file)
		if err != nil {
			log.Warn("nuget: a file cannot be read, what it states is missing", "file", file, "error", err)
			return &Project{Central: map[string]string{}, Properties: map[string]string{}}
		}
		return project
	}
	// MSBuild imports the nearest of each of these into every project
	// below it, so the references they hold are every such project's.
	central, shared, targets := above(CentralVersionsFile), above(buildPropsFile), above(buildTargetsFile)

	u := &unlocked{nl: sbom.NewNodeList(), opts: opts, nodes: map[string]*sbom.Node{}}
	u.root = rootNode(workDir, opts)
	u.nl.AddRootNode(u.root)

	for _, name := range projectFiles {
		project, err := ReadProject(filepath.Join(workDir, name))
		if err != nil {
			log.Warn("nuget: a project file cannot be read and is left out", "file", filepath.Join(workDir, name), "error", err)
			continue
		}
		// What the repository gives every project is for the ones that
		// reference packages in their project file; one that lists
		// them in a packages.config is of the kind that does not.
		references := project.References
		if !hasConfig {
			references = slices.Concat(references, shared.References, targets.References, central.Global)
		}
		for _, reference := range references {
			requested := reference.Requested
			if requested == "" {
				requested = central.Central[strings.ToLower(reference.ID)]
			}
			resolved := *reference
			resolved.Requested = expandProperties(requested,
				project.Properties, central.Properties, shared.Properties, targets.Properties)
			if err := u.addReference(&resolved); err != nil {
				return nil, err
			}
		}
		for _, referenced := range project.ProjectReferences {
			if err := u.addProject(referenced); err != nil {
				return nil, err
			}
		}
	}

	if hasConfig {
		packages, err := ReadPackagesConfig(filepath.Join(workDir, PackagesConfigFile))
		if err != nil {
			log.Warn("nuget: packages.config cannot be read and is left out", "file", filepath.Join(workDir, PackagesConfigFile), "error", err)
		}
		for _, pkg := range packages {
			if err := u.addConfigPackage(pkg); err != nil {
				return nil, err
			}
		}
	}
	return u.nl, nil
}

type unlocked struct {
	nl    *sbom.NodeList
	opts  *api.DecomposerOptions
	root  *sbom.Node
	nodes map[string]*sbom.Node
}

// relate adds a node, once for a key, under the edge given. A
// development dependency waits for its flag.
func (u *unlocked) relate(key string, edge sbom.Edge_Type, build func() *sbom.Node) (*sbom.Node, error) {
	if edge == sbom.Edge_devDependency && !u.opts.IncludeDev {
		return nil, nil
	}
	if node, known := u.nodes[key]; known {
		return node, nil
	}
	node := build()
	u.nodes[key] = node
	if err := u.nl.RelateNodeAtID(node, u.root.GetId(), edge); err != nil {
		return nil, fmt.Errorf("relating %s: %w", node.GetName(), err)
	}
	return node, nil
}

func packageNode(id, version string) *sbom.Node {
	return &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    id,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(purl.TypeNuget, "", id, version, nil, "").ToString(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
}

// addReference adds a package a project file references. One that does
// not flow to what uses the project, an analyzer or a build tool, is a
// development dependency.
func (u *unlocked) addReference(reference *Reference) error {
	edge := sbom.Edge_dependsOn
	if reference.Private {
		edge = sbom.Edge_devDependency
	}
	version := reference.Version()
	node, err := u.relate(strings.ToLower(reference.ID)+"@"+reference.Requested, edge, func() *sbom.Node {
		node := packageNode(reference.ID, version)
		addProperty(node, PropertyType, TypeDirect)
		addProperty(node, PropertyReadFrom, ReadFromProject)
		addProperty(node, PropertyRequested, reference.Requested)
		return node
	})
	if err != nil || node == nil {
		return err
	}
	addProperty(node, PropertyCondition, reference.Condition)
	return nil
}

// addProject adds another project of the solution the project
// references, known by the name of its file.
func (u *unlocked) addProject(referenced string) error {
	base := path.Base(strings.ReplaceAll(referenced, `\`, "/"))
	name := strings.TrimSuffix(base, path.Ext(base))
	if name == "" {
		return nil
	}
	_, err := u.relate("project:"+strings.ToLower(name), sbom.Edge_dependsOn, func() *sbom.Node {
		node := &sbom.Node{
			Id:   uuid.NewString(),
			Type: sbom.Node_PACKAGE,
			Name: name,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(purl.TypeGeneric, "", name, "", nil, "").ToString(),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		addProperty(node, PropertyType, TypeProject)
		addProperty(node, PropertyReadFrom, ReadFromProject)
		return node
	})
	return err
}

// addConfigPackage adds a package of a packages.config.
func (u *unlocked) addConfigPackage(pkg *ConfigPackage) error {
	edge := sbom.Edge_dependsOn
	if pkg.Development {
		edge = sbom.Edge_devDependency
	}
	node, err := u.relate(strings.ToLower(pkg.ID)+"@"+pkg.Version, edge, func() *sbom.Node {
		node := packageNode(pkg.ID, pkg.Version)
		addProperty(node, PropertyReadFrom, ReadFromPackagesConfig)
		return node
	})
	if err != nil || node == nil {
		return err
	}
	addProperty(node, PropertyTarget, pkg.Framework)
	return nil
}

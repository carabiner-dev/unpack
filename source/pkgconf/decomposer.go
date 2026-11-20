// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package pkgconf reads what a C or C++ project says of itself in the
// pkg-config files (.pc, .pc.in) it ships: the packages it installs, and
// what a user of each needs with it.
//
// The fields read and what they become follow pkgconf's own SBOM tools,
// spdxtool and bomtool.
package pkgconf

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
	"github.com/carabiner-dev/unpack/internal/logging"
	"github.com/carabiner-dev/unpack/license"
)

var (
	_ api.Decomposer        = (*Decomposer)(nil)
	_ api.SourceDecomposer  = (*Decomposer)(nil)
	_ api.ContextDecomposer = (*Decomposer)(nil)
	_ api.ContextReporter   = (*Decomposer)(nil)
)

// Properties a node carries.
const (
	// PropertyName is the label a package gives itself, when it is not
	// the name it is asked for by.
	PropertyName = "pkgconf:name"

	// PropertyFile is the pkg-config file a package was read from,
	// relative to the codebase.
	PropertyFile = "pkgconf:file"

	// PropertyRequires says through which list a package is required,
	// once for each: requires, requires.private, requires.internal or
	// requires.shared.
	PropertyRequires = "pkgconf:requires"

	// PropertyConstraint is a range of versions of a required package
	// that will do, as the file writes it (">= 1.2.3").
	PropertyConstraint = "pkgconf:version-constraint"

	// PropertyUnresolved names a property of the file whose value the
	// file does not settle: a placeholder the build fills in.
	PropertyUnresolved = "pkgconf:unresolved"

	// PropertyLicenseFile is where the file says the license text is
	// installed.
	PropertyLicenseFile = "pkgconf:license-file"
)

// virtualPackage is the name pkg-config files require to say which
// pkgconf they need. It is the tool, and no package of the project.
const virtualPackage = "pkgconf"

// New returns a ready-to-use pkg-config decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from a project's pkg-config files.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the files are read in Go, pkgconf is not
// run.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the pkg-config files of a project, as they stand in its source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

// isPCFile says whether a file name is a pkg-config file's or a
// template's of one.
func isPCFile(name string) bool {
	return strings.HasSuffix(name, pcSuffix) || strings.HasSuffix(name, templateSuffix)
}

// FindCodeBases locates the directories holding pkg-config files. Each is
// a codebase: the files of one directory are the packages one project, or
// one part of it, installs.
//
// A file counts when it is one by pkgconf's test and not by its suffix
// alone (see File.Valid), so a directory of other things called .pc is no
// codebase.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	found := []string{}
	for dir, files := range *index {
		if slices.ContainsFunc(files, func(name string) bool {
			if !isPCFile(name) {
				return false
			}
			file, err := ReadFile(filepath.Join(dir, name))
			return err == nil && file.Valid()
		}) {
			found = append(found, dir)
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

// ExtractWithContext reads the pkg-config files of a directory. Each is
// a root of the graph, a package the project installs, with the packages
// its file requires as its dependencies.
//
// A required package is known by its name alone: its own file is on the
// machine that builds the project and not in its source tree, so it has
// no version, only the range the requirement states, and nothing it
// requires in turn is there. A package another file of the directory
// describes is the exception, and is related as it is.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", workDir, err)
	}

	// A package may be there as a file and as the template it was made
	// from, in a build tree. The file is what the template became.
	files := map[string]*File{}
	paths := map[string]string{}
	names := []string{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		name := entry.Name()
		if isPCFile(name) {
			names = append(names, name)
		}
	}
	// Templates first, so that a file of the same package replaces its
	// template.
	sort.Slice(names, func(i, j int) bool {
		ti, tj := strings.HasSuffix(names[i], templateSuffix), strings.HasSuffix(names[j], templateSuffix)
		if ti != tj {
			return ti
		}
		return names[i] < names[j]
	})
	log := logging.FromContext(ctx)
	for _, name := range names {
		file, err := ReadFile(filepath.Join(workDir, name))
		if err != nil {
			return nil, err
		}
		// Not everything called .pc is a pkg-config file.
		if !file.Valid() {
			log.Debug("pkgconf: a file is left out, it lacks properties a pkg-config file must have",
				"file", filepath.Join(workDir, name), "missing", file.Missing())
			continue
		}
		files[file.ID] = file
		paths[file.ID] = name
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no pkg-config files in %s", workDir)
	}

	b := &builder{nl: sbom.NewNodeList(), opts: opts, files: files, nodes: map[string]*sbom.Node{}}
	ids := make([]string, 0, len(files))
	for id := range files {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	// The packages of the directory first, so that one of them requiring
	// another finds it.
	for _, id := range ids {
		node := packageNode(files[id], paths[id], opts)
		b.nodes[id] = node
		b.nl.AddRootNode(node)
	}
	unresolved := 0
	for _, id := range ids {
		file := files[id]
		unresolved += len(file.Unresolved)
		for _, list := range []struct {
			kind string
			deps []Dependency
		}{
			{"requires", file.Requires},
			{"requires.private", file.RequiresPrivate},
			{"requires.internal", file.RequiresInternal},
			{"requires.shared", file.RequiresShared},
		} {
			for i := range list.deps {
				if err := b.require(b.nodes[id], &list.deps[i], list.kind); err != nil {
					return nil, err
				}
			}
		}
	}
	if unresolved > 0 {
		log.Debug(
			"pkgconf: properties hold placeholders the build fills in, their values are not known from the source",
			"codebase", workDir, "properties", unresolved)
	}
	return b.nl, nil
}

type builder struct {
	nl    *sbom.NodeList
	opts  *api.DecomposerOptions
	files map[string]*File
	nodes map[string]*sbom.Node
}

// require relates a package to one it requires. Every list is a
// dependency, as in pkgconf's own SBOMs; which list it was is kept on the
// required package, since a package only needed for static linking is
// not in every build.
func (b *builder) require(from *sbom.Node, dep *Dependency, kind string) error {
	if dep.Name == virtualPackage {
		return nil
	}
	node, known := b.nodes[dep.Name]
	if !known {
		node = &sbom.Node{
			Id:   uuid.NewString(),
			Type: sbom.Node_PACKAGE,
			Name: dep.Name,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
					purl.TypeGeneric, "", dep.Name, "", nil, "").ToString(),
			},
			PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		}
		b.nodes[dep.Name] = node
		b.nl.AddNode(node)
	}
	// What is said of the requirement goes on the required package when
	// it is not one of the project's own, whose properties are its
	// file's.
	if _, own := b.files[dep.Name]; !own {
		addProperty(node, PropertyRequires, kind)
		addProperty(node, PropertyConstraint, dep.Constraint())
	}
	if node.GetId() == from.GetId() {
		return nil
	}
	if err := b.nl.RelateNodeAtID(node, from.GetId(), sbom.Edge_dependsOn); err != nil {
		return fmt.Errorf("relating %s: %w", dep.Name, err)
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

// packageNode renders a package of the project from its file, the way
// pkgconf's spdxtool does: URL as the home page, Source as the download
// location, Maintainer as the supplier, License as the license.
func packageNode(file *File, path string, opts *api.DecomposerOptions) *sbom.Node {
	version := opts.Version
	if version == "" {
		version = file.Version
	}
	node := &sbom.Node{
		Id:          uuid.NewString(),
		Type:        sbom.Node_PACKAGE,
		Name:        file.ID,
		Version:     version,
		Description: file.Description,
		UrlHome:     file.URL,
		UrlDownload: file.Source,
		Copyright:   strings.Join(file.Copyright, "\n"),
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeGeneric, "", file.ID, version, nil, "").ToString(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	for _, expression := range file.Licenses {
		node.Licenses = append(node.Licenses, license.Normalize(expression, ""))
	}
	if supplier := maintainer(file.Maintainer); supplier != nil {
		node.Suppliers = []*sbom.Person{supplier}
	}
	if opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}

	if file.Name != file.ID {
		addProperty(node, PropertyName, file.Name)
	}
	addProperty(node, PropertyFile, path)
	addProperty(node, PropertyLicenseFile, file.LicenseFile)
	for _, keyword := range file.Unresolved {
		addProperty(node, PropertyUnresolved, keyword)
	}
	return node
}

// maintainer reads who a file names as its maintainer: a name followed
// by an address or a website, as pc(5) asks for it. Whether that is a
// person or an organization the file does not say.
func maintainer(value string) *sbom.Person {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if address, err := mail.ParseAddress(value); err == nil {
		name := address.Name
		if name == "" {
			name = address.Address
		}
		return &sbom.Person{Name: name, Email: address.Address}
	}
	// A name and a website.
	fields := strings.Fields(value)
	if last := strings.Trim(fields[len(fields)-1], "<>()"); len(fields) > 1 &&
		(strings.HasPrefix(last, "https://") || strings.HasPrefix(last, "http://")) {
		return &sbom.Person{Name: strings.Join(fields[:len(fields)-1], " "), Url: last}
	}
	return &sbom.Person{Name: value}
}

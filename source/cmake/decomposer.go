// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package cmake reads the dependencies of C and C++ projects built with
// CMake, from the project's CMake files alone.
package cmake

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

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

// Properties a dependency node carries to say how it was read.
const (
	// PropertyStatus is how sure it is that a build has the dependency:
	// required, optional, conditional or disabled (see Status).
	PropertyStatus = "cmake:status"

	// PropertyCommand names a command that asks for the dependency.
	PropertyCommand = "cmake:command"

	// PropertyConstraint is the version range the project accepts.
	PropertyConstraint = "cmake:version-constraint"

	// PropertyPkgConfig names a pkg-config module it is looked up as.
	PropertyPkgConfig = "cmake:pkg-config"

	// PropertyDeclared is a place it is asked for, as file:line.
	PropertyDeclared = "cmake:declared"
)

// New returns a ready-to-use CMake decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from CMake projects.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the files are read in Go, CMake is not run.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the project's CMake files, as they stand in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

// FindCodeBases locates CMake projects: the directories whose
// CMakeLists.txt declares a project, the outermost of them. A project
// holds a CMakeLists.txt in most of its directories, and the projects it
// vendors or carries as examples are below it.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	locations, err := index.FindFileLocations(listsFile)
	if err != nil {
		return nil, err
	}

	projects := []string{}
	for _, loc := range locations {
		data, err := os.ReadFile(filepath.Join(loc, listsFile))
		if err != nil {
			continue
		}
		// A file with a mistake in it still says what came before.
		commands, _ := Parse(string(data)) //nolint:errcheck // see above
		if declaresProject(commands) {
			projects = append(projects, loc)
		}
	}

	outermost := []string{}
	for _, loc := range projects {
		inside := slices.ContainsFunc(projects, func(other string) bool {
			rel, err := filepath.Rel(other, loc)
			return err == nil && other != loc && rel != "." && !strings.HasPrefix(rel, "..")
		})
		if !inside {
			outermost = append(outermost, loc)
		}
	}
	slices.Sort(outermost)
	return outermost, nil
}

// Extract is ExtractWithContext with a background context, for a caller
// that has none to give.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractWithContext(context.Background(), opts)
}

// ExtractWithContext reads the project's CMake files and returns the
// packages they ask for, each a dependency of the project.
//
// The graph is flat: the files say what the project asks for and not
// what those packages ask for in turn.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}

	project, err := ReadProject(workDir)
	if err != nil {
		return nil, fmt.Errorf("reading the CMake project: %w", err)
	}

	log := logging.FromContext(ctx)
	if len(project.Skipped) > 0 {
		log.Warn("cmake: files could not be read as CMake, what they ask for after the mistake is missing",
			"files", len(project.Skipped))
		log.Debug("cmake: files that could not be read", "items", project.Skipped)
	}

	nl := sbom.NewNodeList()
	root := rootNode(project, opts)
	nl.AddRootNode(root)

	left := 0
	for _, dep := range project.Dependencies {
		edge, included := edgeFor(dep, opts)
		if !included {
			left++
			continue
		}
		if err := nl.RelateNodeAtID(dependencyNode(dep), root.GetId(), edge); err != nil {
			return nil, fmt.Errorf("relating %s: %w", dep.Name, err)
		}
	}
	if left > 0 {
		log.Debug("cmake: dependencies left out, they are behind options that are off by default",
			"left_out", left, "found", len(project.Dependencies))
	}
	return nl, nil
}

// edgeFor says how a dependency relates to the project and whether the
// options include it.
//
// What the default configuration asks for is always in, required or not.
// Optional does not mean here what it means to a package manager, where
// an optional dependency is one not installed unless asked for: a
// find_package with no REQUIRED uses the package when the machine has it,
// and a machine set up to build the project does. Leaving those out
// would make the inventory of a project that requires little look
// complete. The same goes for what is behind a condition the files do
// not settle: it is in some build, and nothing says it is not in this
// one. Both are optional dependencies in the graph, which is what they
// are to the build.
//
// Only what the default configuration turns off waits for the flag: a
// dependency behind an option that is off is in no build that did not
// ask for it.
func edgeFor(dep *Dependency, opts *api.DecomposerOptions) (sbom.Edge_Type, bool) {
	switch dep.Status {
	case StatusRequired:
		return sbom.Edge_dependsOn, true
	case StatusDisabled:
		return sbom.Edge_optionalDependency, opts.IncludeOptional
	case StatusOptional, StatusConditional:
		return sbom.Edge_optionalDependency, true
	}
	return sbom.Edge_optionalDependency, true
}

func rootNode(project *Project, opts *api.DecomposerOptions) *sbom.Node {
	version := opts.Version
	if version == "" {
		version = project.Version
	}
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    project.Name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeGeneric, "", project.Name, version, nil, "").ToString(),
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

func dependencyNode(dep *Dependency) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    dep.Name,
		Version: dep.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): dependencyPurl(dep),
		},
		UrlDownload: dep.URL,
	}
	if dep.Repository != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  dep.Repository,
			Type: sbom.ExternalReference_VCS,
		})
	}
	if algo := hashAlgorithm(dep.HashAlgo); algo != sbom.HashAlgorithm_UNKNOWN && dep.Hash != "" {
		node.Hashes = map[int32]string{int32(algo): dep.Hash}
	}

	property := func(name, value string) {
		if value != "" {
			node.Properties = append(node.Properties, &sbom.Property{Name: name, Data: value})
		}
	}
	property(PropertyStatus, dep.Status.String())
	property(PropertyConstraint, dep.Constraint)
	for _, command := range dep.Commands {
		property(PropertyCommand, command)
	}
	for _, module := range dep.PkgConfig {
		property(PropertyPkgConfig, module)
	}
	for _, where := range dep.Declared {
		property(PropertyDeclared, where)
	}
	return node
}

// dependencyPurl names a dependency. One fetched from a repository on a
// code host is named as that repository; the rest are only known by the
// name the project asks for them under, which is no ecosystem's.
func dependencyPurl(dep *Dependency) string {
	if host, owner, repo, ok := hostedRepository(dep.Repository); ok {
		return purl.NewPackageURL(host, owner, repo, dep.Version, nil, "").ToString()
	}
	return purl.NewPackageURL(purl.TypeGeneric, "", dep.Name, dep.Version, nil, "").ToString()
}

// hostedRepository reads the owner and name of a repository on GitHub,
// GitLab or Bitbucket off its URL.
func hostedRepository(repository string) (purlType, owner, repo string, ok bool) {
	parsed, err := url.Parse(repository)
	if err != nil || parsed.Host == "" {
		return "", "", "", false
	}
	types := map[string]string{
		"github.com": purl.TypeGithub, "gitlab.com": purl.TypeGitlab, "bitbucket.org": purl.TypeBitbucket,
	}
	purlType, known := types[strings.ToLower(parsed.Hostname())]
	parts := strings.Split(strings.Trim(strings.TrimSuffix(parsed.Path, ".git"), "/"), "/")
	if !known || len(parts) < 2 || parts[0] == "" || parts[len(parts)-1] == "" {
		return "", "", "", false
	}
	// GitLab nests groups: all but the last element is the namespace.
	return purlType, strings.ToLower(strings.Join(parts[:len(parts)-1], "/")), strings.ToLower(parts[len(parts)-1]), true
}

func hashAlgorithm(name string) sbom.HashAlgorithm {
	switch strings.ToUpper(name) {
	case "MD5":
		return sbom.HashAlgorithm_MD5
	case "SHA1":
		return sbom.HashAlgorithm_SHA1
	case "SHA256":
		return sbom.HashAlgorithm_SHA256
	case "SHA384":
		return sbom.HashAlgorithm_SHA384
	case "SHA512":
		return sbom.HashAlgorithm_SHA512
	}
	return sbom.HashAlgorithm_UNKNOWN
}

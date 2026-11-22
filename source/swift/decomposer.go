// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package swift reads the dependencies of projects managed with the
// Swift Package Manager, from its lockfile, Package.resolved.
//
// Packages are named, versioned and identified as SwiftPM itself does in
// the SBOMs it generates (SE-0509, Swift 6.4), so that the two agree on
// what a package is.
package swift

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
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

// Properties a dependency node carries.
const (
	// PropertyKind is where the package is fetched from:
	// remoteSourceControl, localSourceControl or registry.
	PropertyKind = "swift:kind"

	// PropertyBranch is the branch a package follows, when it is pinned
	// to one and not to a version. Its version is then the commit.
	PropertyBranch = "swift:branch"

	// PropertyRevision is the commit the package is pinned at.
	PropertyRevision = "swift:revision"
)

// New returns a ready-to-use Swift decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from Swift Package Manager projects.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the lockfile is read in Go, Swift is not
// run.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the lockfile, as it stands in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

// FindCodeBases locates Swift projects by their Package.resolved: beside
// the Package.swift of a package, and for an Xcode project or workspace
// inside its bundle, under xcshareddata/swiftpm.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations(ResolvedFile)
}

// Extract is ExtractWithContext with a background context, for a caller
// that has none to give.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractWithContext(context.Background(), opts)
}

// ExtractWithContext reads the lockfile and returns the packages it pins,
// each a dependency of the project.
//
// The graph is flat. Package.resolved lists the packages a graph resolved
// to and not the edges between them: those are in the Package.swift of
// each package, which is a Swift program. SwiftPM's own SBOMs have the
// edges, and the products of each package, because SwiftPM evaluates
// those programs.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	resolved, err := ReadResolved(filepath.Join(workDir, ResolvedFile))
	if err != nil {
		return nil, err
	}
	if resolved.Version > newestSchema {
		logging.FromContext(ctx).Warn("swift: Package.resolved is of a schema newer than the ones known, it is read as the newest known",
			"file", filepath.Join(workDir, ResolvedFile), "schema", resolved.Version, "known", newestSchema)
	}

	nl := sbom.NewNodeList()
	root := rootNode(workDir, opts)
	nl.AddRootNode(root)
	for _, pin := range resolved.Pins {
		if err := nl.RelateNodeAtID(pinNode(pin), root.GetId(), sbom.Edge_dependsOn); err != nil {
			return nil, fmt.Errorf("relating %s: %w", pin.Identity, err)
		}
	}
	return nl, nil
}

// newestSchema is the newest schema of Package.resolved known.
const newestSchema = 3

// Elements of the path Xcode keeps a lockfile at, inside the bundle of a
// project or a workspace:
//
//	App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved
//	App.xcworkspace/xcshareddata/swiftpm/Package.resolved
var xcodeBundle = regexp.MustCompile(`^(.+)\.(xcodeproj|xcworkspace)$`)

// projectName names the project a lockfile is of: the directory it is
// in, and for one Xcode keeps inside a bundle, the project or workspace
// the bundle is of.
func projectName(workDir string) string {
	abs, err := filepath.Abs(workDir)
	if err != nil {
		abs = workDir
	}
	if filepath.Base(abs) == "swiftpm" && filepath.Base(filepath.Dir(abs)) == "xcshareddata" {
		// The outermost bundle: a project's own workspace is inside it.
		name := ""
		for dir := filepath.Dir(filepath.Dir(abs)); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
			match := xcodeBundle.FindStringSubmatch(filepath.Base(dir))
			if match == nil {
				break
			}
			name = match[1]
		}
		if name != "" {
			return name
		}
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
			// A package's identity is in lower case.
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeSwift, "", strings.ToLower(name), opts.Version, nil, "").ToString(),
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

var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// pinNode renders a pinned package as SwiftPM's SBOMs do: named by its
// identity, versioned by its version or else its commit, with the
// repository and commit it comes from.
func pinNode(pin *Pin) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    pin.Identity,
		Version: pin.ComponentVersion(),
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): pin.PURL(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	if pin.Location != "" {
		reference := &sbom.ExternalReference{Url: pin.Location, Type: sbom.ExternalReference_VCS}
		if commitSHA.MatchString(pin.Revision) {
			reference.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA1): pin.Revision}
		}
		node.ExternalReferences = append(node.ExternalReferences, reference)
	}
	for _, property := range []struct{ name, value string }{
		{PropertyKind, pin.Kind}, {PropertyBranch, pin.Branch}, {PropertyRevision, pin.Revision},
	} {
		if property.value != "" {
			node.Properties = append(node.Properties, &sbom.Property{Name: property.name, Data: property.value})
		}
	}
	return node
}

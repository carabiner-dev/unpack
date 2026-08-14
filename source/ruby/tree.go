// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file turns a Gemfile.lock into the dependency graph one platform
// sees. A gem may resolve once per platform, so the builder selects each
// gem's variant for the target — native builds preferred, the pure-Ruby
// variant as the fallback — and the checksum, when the lock carries them,
// is the selected artifact's.
//
// The lock has no project name and no groups: the root borrows the
// directory's name, and every direct dependency is a plain edge, since
// which of them are development-only lives in the Gemfile's Ruby code.

type rubyBuilder struct {
	lock    *GemLockfile
	workDir string
	opts    *api.DecomposerOptions

	// platforms are the target's gem platforms, most specific first.
	platforms []string

	nl     *sbom.NodeList
	byName map[string][]*GemSpec
	nodes  map[string]*sbom.Node

	// selected records which variant each node was built from, which is
	// what enrichment needs to know a node's registry identity.
	selected map[string]*GemSpec
}

func newRubyBuilder(lock *GemLockfile, workDir string, opts *api.DecomposerOptions, platform string) (*rubyBuilder, error) {
	candidates, err := gemPlatforms(platform)
	if err != nil {
		return nil, err
	}

	rb := &rubyBuilder{
		lock:      lock,
		workDir:   workDir,
		opts:      opts,
		platforms: candidates,
		nl:        sbom.NewNodeList(),
		byName:    map[string][]*GemSpec{},
		nodes:     map[string]*sbom.Node{},
		selected:  map[string]*GemSpec{},
	}
	for _, source := range lock.Sources {
		for _, spec := range source.Specs {
			rb.byName[spec.Name] = append(rb.byName[spec.Name], spec)
		}
	}
	return rb, nil
}

// build walks the lock from the direct dependencies.
func (rb *rubyBuilder) build() (*sbom.NodeList, error) {
	root := rb.rootNode()
	rb.nl.AddRootNode(root)

	for _, name := range rb.lock.Dependencies {
		if err := rb.addEdge(name, root); err != nil {
			return nil, err
		}
	}
	return rb.nl, nil
}

// rootNode builds the project's node. The lock names no project, so the
// directory lends its name; the caller may know the version.
func (rb *rubyBuilder) rootNode() *sbom.Node {
	abs, err := filepath.Abs(rb.workDir)
	if err != nil {
		abs = rb.workDir
	}
	name := filepath.Base(abs)

	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           name,
		Version:        rb.opts.Version,
		Identifiers:    map[int32]string{},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	purlValue := "pkg:gem/" + name
	if rb.opts.Version != "" {
		purlValue += "@" + rb.opts.Version
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlValue

	if rb.opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): rb.opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

// addEdge resolves a gem name to the target platform's variant, relates
// it, and walks into it when it is new.
func (rb *rubyBuilder) addEdge(name string, parent *sbom.Node) error {
	spec := rb.selectSpec(name)
	if spec == nil {
		return fmt.Errorf("the lockfile has no spec for %s", name)
	}

	node, known := rb.nodes[name]
	if !known {
		node = rb.specNode(spec)
		rb.nodes[name] = node
		rb.selected[name] = spec
		rb.nl.AddNode(node)
	}
	if err := rb.nl.RelateNodeAtID(node, parent.GetId(), sbom.Edge_dependsOn); err != nil {
		return err
	}
	if known {
		return nil
	}

	for _, dep := range spec.Dependencies {
		if err := rb.addEdge(dep, node); err != nil {
			return err
		}
	}
	return nil
}

// selectSpec picks a gem's variant for the target platform: the first
// candidate platform any variant matches, the pure-Ruby variant otherwise.
func (rb *rubyBuilder) selectSpec(name string) *GemSpec {
	variants := rb.byName[name]
	if len(variants) == 0 {
		return nil
	}

	for _, platform := range rb.platforms {
		for _, variant := range variants {
			if variant.Platform == platform {
				return variant
			}
		}
	}
	for _, variant := range variants {
		if variant.Platform == "" {
			return variant
		}
	}
	// Only foreign-platform builds: the resolution is honest about the
	// name and version even when no artifact fits the target.
	return variants[0]
}

// specNode builds the node of one resolved gem.
func (rb *rubyBuilder) specNode(spec *GemSpec) *sbom.Node {
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    spec.Name,
		Version: spec.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): gemPurl(spec),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}

	switch spec.Source.Type {
	case "gem":
		// The registry's download URL is conventional:
		// <remote>downloads/<name>-<full version>.gem.
		if remote := spec.Source.Remote; remote != "" {
			node.UrlDownload = strings.TrimSuffix(remote, "/") +
				"/downloads/" + spec.Name + "-" + spec.FullVersion() + ".gem"
		}
	case "git":
		url := spec.Source.Remote
		if spec.Source.Revision != "" {
			url += "#" + spec.Source.Revision
		}
		node.UrlDownload = url
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  url,
			Type: sbom.ExternalReference_VCS,
		})
	}
	// A path source points at local content with no address to record.

	// The checksum, when the lock carries them, is the selected
	// artifact's: the platform variants hash differently.
	if sum := rb.lock.Checksums[spec.Name+" "+spec.FullVersion()]; sum != "" {
		node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): sum}
	}
	return node
}

// gemPurl names a gem, the platform variant as a qualifier.
func gemPurl(spec *GemSpec) string {
	purl := fmt.Sprintf("pkg:gem/%s@%s", spec.Name, spec.Version)
	if spec.Platform != "" {
		purl += "?platform=" + spec.Platform
	}
	return purl
}

// gemPlatforms translates an os[/arch] target into gem platform names,
// most specific first. Linux prefers the glibc builds and never selects a
// musl one, the same assumption the Python wheel selection makes; the
// plain unsuffixed form predates the split and is glibc in practice.
func gemPlatforms(platform string) ([]string, error) {
	goos, goarch, _ := strings.Cut(platform, "/")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	const archArm64 = "arm64"
	arches := map[string]string{
		"amd64": "x86_64", archArm64: archArm64, "386": "x86", "arm": "arm",
	}
	arch, ok := arches[goarch]
	if !ok {
		return nil, fmt.Errorf("unknown architecture %q", goarch)
	}

	switch goos {
	case "linux":
		if arch == archArm64 {
			arch = "aarch64"
		}
		return []string{arch + "-linux-gnu", arch + "-linux"}, nil
	case "darwin", "macos":
		return []string{arch + "-darwin", "universal-darwin"}, nil
	case "windows":
		if arch == "x86_64" {
			return []string{"x64-mingw-ucrt", "x64-mingw32"}, nil
		}
		return []string{arch + "-mingw32"}, nil
	default:
		return nil, fmt.Errorf("unknown operating system %q", goos)
	}
}

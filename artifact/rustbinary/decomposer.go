// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package rustbinary implements the artifact decomposer for Rust
// executables built with cargo-auditable. Such binaries carry a
// zlib-compressed JSON record of the crates linked into them, with
// versions, sources, kinds and the edges among them, in a linker section
// named .dep-v0. The decomposer reads that record and renders it with the
// Rust source decomposer's node conventions, so a binary and the Cargo
// project it came from produce the same shape of graph.
package rustbinary

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/artifact/internal/executable"
	"github.com/carabiner-dev/unpack/source/rust"
)

var (
	_ api.Decomposer      = (*Decomposer)(nil)
	_ api.SubjectDefaults = (*Decomposer)(nil)
)

// Name is the name the decomposer is registered under in the artifact
// unpacker, and the key options refer to it by.
const Name = "rustbinary"

// SectionName is the linker section cargo-auditable stores the dependency
// record in, in every object format.
const SectionName = ".dep-v0"

// maxRecordSize bounds the decompressed record. Real ones are kilobytes;
// the bound keeps a hostile section from filling memory.
const maxRecordSize = 64 << 20

// Sources as cargo-auditable records them.
const (
	SourceCratesIO = "crates.io"
	SourceLocal    = "local"
)

// Property names recorded on nodes.
const (
	// PropertySource is set on packages not from crates.io: "git",
	// "local", "registry" or another source cargo-auditable records.
	PropertySource = "cargo:source"

	// PropertyFormat is set on the root with the record's format revision.
	PropertyFormat = "cargo-auditable:format"
)

// VersionInfo is the dependency record cargo-auditable embeds, as the
// auditable-serde crate defines it.
type VersionInfo struct {
	// Packages lists every crate in the build, in an order Dependencies
	// indexes into.
	Packages []Package `json:"packages"`

	// Format is the record's format revision.
	Format int `json:"format"`
}

// Package is one crate in the record.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`

	// Source is where the crate came from: "crates.io", "git", "local",
	// "registry" or a free-form value.
	Source string `json:"source"`

	// Kind is "runtime" (the default, omitted) or "build". A build
	// dependency's own dependencies are recorded as build too.
	Kind string `json:"kind,omitempty"`

	// Dependencies indexes the packages this one depends on.
	Dependencies []int `json:"dependencies,omitempty"`

	// Root marks the crate the binary was built from.
	Root bool `json:"root,omitempty"`
}

// Decomposer reads dependency data out of cargo-auditable Rust executables.
type Decomposer struct{}

// New returns a Rust binary decomposer.
func New() *Decomposer { return &Decomposer{} }

// Name returns the decomposer's registration name.
func (d *Decomposer) Name() string { return Name }

// DefaultSubjects lists the parents the decomposer runs under by default:
// a container image or a system root, where executables are the payload,
// and not a codebase.
func (d *Decomposer) DefaultSubjects() []string {
	return []string{"image", "system"}
}

// DefaultOptions returns the Rust source decomposer's options, which the
// crates.io enrichment reads: set them as this decomposer's driver options
// to control the request concurrency.
func (d *Decomposer) DefaultOptions() any {
	return rust.New().DefaultOptions()
}

// Requirements returns nothing: the decomposer is pure Go.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement {
	return nil
}

// Extract reads the executable at opts.WorkDir. It is the plain api.Decomposer
// entry point; the artifact unpacker uses ExtractArtifact.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("rustbinary decomposer needs a WorkDir naming the executable")
	}
	f, err := os.Open(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("opening executable: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	return d.ExtractArtifact(f, opts.WorkDir, opts)
}

// Matches reports whether the file looks like an executable in a format
// the section reader understands: ELF, PE or Mach-O. Whether it carries a
// cargo-auditable record is settled by ExtractArtifact.
func (d *Decomposer) Matches(_ fs.FileInfo, header []byte) bool {
	return executable.Magic(header)
}

// ExtractArtifact reads the cargo-auditable record in the executable and
// returns the crate graph: the root crate the binary was built from, with
// the crates linked into it as its descendants. Returns (nil, nil) when the
// file carries no record, which is what every executable not built with
// cargo-auditable looks like. A record that is present but unreadable is
// an error: the file is one of ours and it is broken.
func (d *Decomposer) ExtractArtifact(ra io.ReaderAt, _ string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}

	data, err := executable.Section(ra, SectionName)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}

	info, err := DecodeRecord(data)
	if err != nil {
		return nil, fmt.Errorf("decoding the cargo-auditable record: %w", err)
	}

	nl, nodes, err := BuildNodeList(info, opts)
	if err != nil {
		return nil, err
	}

	if opts.Networking >= api.NetworkEssential && len(nodes) > 0 {
		concurrency := 0
		if rOpts, ok := opts.GetDriverOptions(d).(*rust.Options); ok {
			concurrency = rOpts.Concurrency
		}
		rust.EnrichNodes(rust.NewCratesIOClient(concurrency), nodes)
	}
	return nl, nil
}

// DecodeRecord inflates and parses the contents of the .dep-v0 section.
func DecodeRecord(data []byte) (*VersionInfo, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("opening the compressed record: %w", err)
	}
	defer zr.Close() //nolint:errcheck // read-only

	raw, err := io.ReadAll(io.LimitReader(zr, maxRecordSize+1))
	if err != nil {
		return nil, fmt.Errorf("inflating the record: %w", err)
	}
	if len(raw) > maxRecordSize {
		return nil, fmt.Errorf("the record inflates past %d bytes", maxRecordSize)
	}

	info := &VersionInfo{}
	if err := json.Unmarshal(raw, info); err != nil {
		return nil, fmt.Errorf("parsing the record: %w", err)
	}
	if len(info.Packages) == 0 {
		return nil, errors.New("the record lists no packages")
	}
	return info, nil
}

// BuildNodeList renders a record as a protobom NodeList rooted at the crate
// the binary was built from, and returns the crates.io packages by key for
// enrichment. Every crate reachable from the root becomes a node, related
// to what requires it with dependsOn, or buildDependency for the crates
// cargo-auditable marks as build dependencies. Build dependencies, and
// everything only they pull in, are left out unless opts.IncludeBuild is
// set: they are what built the binary, not what runs in it.
func BuildNodeList(info *VersionInfo, opts *api.DecomposerOptions) (*sbom.NodeList, map[rust.PackageKey]*sbom.Node, error) {
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}
	rootIdx := -1
	for i := range info.Packages {
		if info.Packages[i].Root {
			rootIdx = i
			break
		}
	}
	if rootIdx < 0 {
		return nil, nil, errors.New("the record marks no root package")
	}
	for i, p := range info.Packages {
		for _, dep := range p.Dependencies {
			if dep < 0 || dep >= len(info.Packages) {
				return nil, nil, fmt.Errorf("package %d (%s) depends on index %d, out of range", i, p.Name, dep)
			}
		}
	}

	nl := sbom.NewNodeList()
	nodes := make([]*sbom.Node, len(info.Packages))
	cratesIO := make(map[rust.PackageKey]*sbom.Node)

	root := &info.Packages[rootIdx]
	version := root.Version
	if opts.Version != "" {
		version = opts.Version
	}
	rootNode := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    root.Name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): fmt.Sprintf("pkg:cargo/%s@%s", root.Name, version),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
		Properties: []*sbom.Property{
			{Name: PropertyFormat, Data: fmt.Sprint(info.Format)},
		},
	}
	if root.Source != SourceCratesIO {
		rootNode.Properties = append(rootNode.Properties, &sbom.Property{Name: PropertySource, Data: root.Source})
	}
	if opts.CommitHash != "" {
		rootNode.ExternalReferences = append(rootNode.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	nl.AddRootNode(rootNode)
	nodes[rootIdx] = rootNode

	// Walk from the root, creating each crate's node on first sight and
	// relating it to whatever requires it.
	queue := []int{rootIdx}
	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]
		for _, to := range info.Packages[from].Dependencies {
			dep := &info.Packages[to]
			if dep.Kind == "build" && !opts.IncludeBuild {
				continue
			}
			edge := sbom.Edge_dependsOn
			if dep.Kind == "build" {
				edge = sbom.Edge_buildDependency
			}
			if nodes[to] == nil {
				nodes[to] = packageNode(dep)
				if dep.Source == SourceCratesIO {
					cratesIO[rust.PackageKey{Name: dep.Name, Version: dep.Version}] = nodes[to]
				}
				queue = append(queue, to)
			}
			if err := nl.RelateNodeAtID(nodes[to], nodes[from].GetId(), edge); err != nil {
				return nil, nil, fmt.Errorf("relating %s to %s: %w", dep.Name, info.Packages[from].Name, err)
			}
		}
	}
	return nl, cratesIO, nil
}

// packageNode builds the node for a dependency the way the Rust source
// decomposer does. Crates that are not on crates.io get no download URL
// there and carry their source as a property instead.
func packageNode(p *Package) *sbom.Node {
	node := rust.NewPackageNode(p.Name, p.Version, "")
	if p.Source != SourceCratesIO {
		node.UrlDownload = ""
		node.Properties = append(node.Properties, &sbom.Property{Name: PropertySource, Data: p.Source})
	}
	return node
}

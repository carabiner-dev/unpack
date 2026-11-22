// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package javaarchive reads the packages bundled in Java archives: jars,
// and the WARs, EARs and executable jars that carry their dependencies
// inside them.
package javaarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"

	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/internal/logging"
)

var (
	_ api.Decomposer      = (*Decomposer)(nil)
	_ api.SubjectDefaults = (*Decomposer)(nil)
	_ api.ContextReporter = (*Decomposer)(nil)
)

// Name is the name the decomposer is registered under in the artifact
// unpacker, and the key options refer to it by.
const Name = "javaarchive"

// Properties a node carries.
const (
	// PropertyIdentifiedBy says where a package's name and version were
	// read from: pom.properties, manifest or filename.
	PropertyIdentifiedBy = "java:identified-by"

	// PropertyEmbedding says how a package is in the archive that holds
	// it: nested, as an archive of its own, or shaded, unpacked into it.
	PropertyEmbedding = "java:embedding"

	// PropertyPath is where a nested archive is inside the one that
	// holds it.
	PropertyPath = "java:path"

	// PropertyLicenseFrom says where a package's license was read:
	// pom.xml, manifest or license-file.
	PropertyLicenseFrom = "java:license-from"

	// PropertyMainClass is the class an archive's manifest names to run.
	PropertyMainClass = "java:main-class"
)

// How a package is in the archive that holds it.
const (
	EmbeddingNested = "nested"
	EmbeddingShaded = "shaded"
)

// Decomposer reads dependency data out of Java archives.
type Decomposer struct{}

// New returns a Java archive decomposer.
func New() *Decomposer { return &Decomposer{} }

// Name returns the decomposer's registration name.
func (d *Decomposer) Name() string { return Name }

// DefaultSubjects lists the parents the decomposer runs under by default:
// a container image or a system root, where archives are what is
// deployed. A codebase is not among them: the jars lying in a source
// tree are build outputs and test fixtures.
func (d *Decomposer) DefaultSubjects() []string { return []string{"image", "system"} }

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the decomposer is pure Go.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// out of an archive that is already built.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextAnalyzed }

// zipMagic opens a zip file.
var zipMagic = []byte("PK\x03\x04")

// Matches reports whether a file may be a Java archive: by its name when
// it is known, and by the magic number of a zip otherwise. An executable
// jar may open with a launch script and not with the magic number, so a
// name is enough.
func (d *Decomposer) Matches(info fs.FileInfo, header []byte) bool {
	if info != nil {
		return IsArchiveName(info.Name())
	}
	return bytes.HasPrefix(header, zipMagic)
}

// Extract reads the archive at opts.WorkDir. It is the plain
// api.Decomposer entry point; the artifact unpacker uses ExtractArtifact.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, errors.New("javaarchive decomposer needs a WorkDir naming the archive")
	}
	f, err := os.Open(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("opening archive: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	return d.ExtractArtifact(f, opts.WorkDir, opts)
}

// ExtractArtifact is ExtractArtifactWithContext with a background context,
// for a caller that has none to give.
func (d *Decomposer) ExtractArtifact(ra io.ReaderAt, name string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	return d.ExtractArtifactWithContext(context.Background(), ra, name, opts)
}

// ExtractArtifactWithContext reads the archive and returns the package it
// is, with the packages bundled in it as its dependencies: the archives
// nested in it, each with what is nested in it in turn, and the packages
// unpacked into it. Returns (nil, nil) for a file that is no zip.
//
// The edges say what is bundled in what, which is what an archive
// records. Which of the bundled packages requires which is not in it.
func (d *Decomposer) ExtractArtifactWithContext(
	ctx context.Context, ra io.ReaderAt, name string, _ *api.DecomposerOptions,
) (*sbom.NodeList, error) {
	size, err := sizeOf(ra)
	if err != nil {
		return nil, fmt.Errorf("sizing %q: %w", name, err)
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		// Not a zip: a file that only has the name of an archive.
		return nil, nil //nolint:nilerr // disowning the file is the contract
	}

	archive := readArchive(zr, path.Base(name), 0)

	b := &builder{nl: sbom.NewNodeList(), nodes: map[string]*sbom.Node{}, log: logging.FromContext(ctx).With("archive", name)}
	root := archiveNode(archive)
	b.nl.AddRootNode(root)
	if err := b.add(archive, root); err != nil {
		return nil, err
	}
	return b.nl, nil
}

type builder struct {
	nl    *sbom.NodeList
	nodes map[string]*sbom.Node
	log   interface{ Debug(string, ...any) }
}

// add relates what an archive bundles to its node.
func (b *builder) add(archive *Archive, node *sbom.Node) error {
	for _, skipped := range archive.Skipped {
		b.log.Debug("javaarchive: a nested archive was not read", "entry", skipped)
	}
	for i := range archive.Shaded {
		id := &archive.Shaded[i]
		key := "shaded:" + coordinate(id)
		shaded, known := b.nodes[key]
		if !known {
			shaded = identityNode(id)
			addProperty(shaded, PropertyEmbedding, EmbeddingShaded)
			b.nodes[key] = shaded
			b.nl.AddNode(shaded)
		}
		if err := b.relate(node, shaded); err != nil {
			return err
		}
	}
	for _, nested := range archive.Nested {
		// The same file bundled twice, in two WARs of an EAR, is one
		// package.
		key := "nested:" + nested.SHA256
		child, known := b.nodes[key]
		if !known {
			child = archiveNode(nested)
			b.nodes[key] = child
			b.nl.AddNode(child)
		}
		if err := b.relate(node, child); err != nil {
			return err
		}
		if known {
			continue
		}
		if err := b.add(nested, child); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) relate(from, to *sbom.Node) error {
	if from.GetId() == to.GetId() {
		return nil
	}
	if err := b.nl.RelateNodeAtID(to, from.GetId(), sbom.Edge_dependsOn); err != nil {
		return fmt.Errorf("relating %s: %w", to.GetName(), err)
	}
	return nil
}

// identityNode renders a package from who it is: a Maven artifact when
// its coordinates are known, and a package known by a name alone
// otherwise.
func identityNode(id *Identity) *sbom.Node {
	identifier := purl.NewPackageURL(purl.TypeGeneric, "", id.Name, id.Version, nil, "")
	if id.Source == SourcePOM {
		identifier = purl.NewPackageURL(purl.TypeMaven, id.Group, id.Name, id.Version, nil, "")
	}
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    id.Name,
		Version: id.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): identifier.ToString(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	if id.Vendor != "" {
		node.Suppliers = []*sbom.Person{{Name: id.Vendor, IsOrg: true}}
	}
	node.Licenses = slices.Clone(id.Licenses)
	addProperty(node, PropertyIdentifiedBy, id.Source)
	addProperty(node, PropertyLicenseFrom, id.LicenseSource)
	return node
}

// archiveNode renders an archive: who it is, and for one nested in
// another where it is and what its file hashes to.
func archiveNode(archive *Archive) *sbom.Node {
	node := identityNode(&archive.Identity)
	if archive.MainClass != "" {
		node.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
		addProperty(node, PropertyMainClass, archive.MainClass)
	}
	if archive.Path != "" {
		addProperty(node, PropertyEmbedding, EmbeddingNested)
		addProperty(node, PropertyPath, archive.Path)
	}
	if archive.SHA256 != "" {
		node.Hashes = map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): archive.SHA256,
			int32(sbom.HashAlgorithm_SHA1):   archive.SHA1,
		}
	}
	return node
}

func addProperty(node *sbom.Node, name, value string) {
	if value != "" {
		node.Properties = append(node.Properties, &sbom.Property{Name: name, Data: value})
	}
}

// sizeOf returns the size of what a reader gives access to. A zip is read
// from its end, so the size is needed, and a ReaderAt does not state it:
// the common ones do in their own ways, and the rest are measured.
func sizeOf(ra io.ReaderAt) (int64, error) {
	switch sized := ra.(type) {
	case interface{ Size() int64 }:
		return sized.Size(), nil
	case interface{ Stat() (fs.FileInfo, error) }:
		info, err := sized.Stat()
		if err != nil {
			return 0, err
		}
		return info.Size(), nil
	}

	// Find the end by reading: double a bound until a read there fails,
	// then close in on the last byte.
	probe := make([]byte, 1)
	readable := func(offset int64) bool {
		n, _ := ra.ReadAt(probe, offset) //nolint:errcheck // a short read is the answer
		return n == 1
	}
	if !readable(0) {
		return 0, nil
	}
	low, high := int64(0), int64(1)
	for readable(high) {
		low, high = high, high*2
	}
	for low+1 < high {
		middle := low + (high-low)/2
		if readable(middle) {
			low = middle
		} else {
			high = middle
		}
	}
	return high, nil
}

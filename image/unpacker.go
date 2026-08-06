// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/sync/errgroup"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system"
)

// Ensure the image unpacker satisfies the unified Unpacker interface.
var _ api.Unpacker = (*Unpacker)(nil)

// Register the image unpacker so that subjects of type "image" are routed
// here by the registry.
func init() {
	api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}

// ExtractionMode selects how the unpacker reads the image filesystem.
type ExtractionMode int

const (
	// ModeSquash flattens all layers into a single filesystem, the way a
	// container runtime presents the image, and extracts from the result.
	ModeSquash ExtractionMode = iota

	// ModePerLayer extracts from each layer individually. Not implemented
	// yet.
	ModePerLayer
)

// Options configures the image unpacker.
type Options struct {
	// Mode selects squashed or per-layer extraction. Defaults to ModeSquash.
	Mode ExtractionMode

	// IncludeFiles is passed through to the system decomposers: when set,
	// every file installed by a package is emitted as a Node related to its
	// package.
	IncludeFiles bool

	// RecordLayers adds one structural node per image layer, related to
	// the image through a contains edge. Layers are identified by their
	// diff id — the digest of the uncompressed layer — and carry no
	// packages: the package inventory always reads from the squashed
	// filesystem.
	RecordLayers bool

	// Hooks receives download progress notifications, e.g. to render a
	// progress indicator. Optional.
	Hooks *PullHooks
}

// DefaultOptions is the zero-value configuration used by NewUnpacker.
var DefaultOptions = Options{}

// NewUnpacker returns an image unpacker with the default options.
func NewUnpacker() *Unpacker {
	return &Unpacker{Options: DefaultOptions}
}

// Unpacker extracts dependency data from container images. It downloads the
// image, squashes its layers into the filesystem a running container would
// see, and reads the installed system packages out of it.
type Unpacker struct {
	Options Options
}

// Extract pulls the image referenced by the subject — or reads it from
// the subject's archive — and returns its dependency graph: a node
// describing the image with the system packages found in its filesystem
// as descendants.
func (u *Unpacker) Extract(ctx context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
	if subject == nil {
		return nil, fmt.Errorf("image unpacker received a nil subject")
	}
	ref, ok := subject.(*Reference)
	if !ok {
		return nil, fmt.Errorf(
			"image unpacker cannot process subject of type %q", subject.DecomposableType(),
		)
	}
	if u.Options.Mode == ModePerLayer {
		return nil, fmt.Errorf("per-layer extraction is not implemented yet")
	}

	if ref.Archive != "" {
		return u.extractArchive(ctx, ref)
	}

	nref, err := name.ParseReference(ref.Ref)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", ref.Ref, err)
	}

	desc, err := remote.Get(nref, u.remoteOptions(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("fetching %q: %w", ref.Ref, err)
	}

	var nl *sbom.NodeList
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("reading image index %q: %w", ref.Ref, err)
		}
		nl, err = u.extractIndex(ctx, ref.Ref, nref, idx)
		if err != nil {
			return nil, err
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("reading image %q: %w", ref.Ref, err)
		}
		nl, err = u.extractImage(ctx, ref.Ref, nref, img)
		if err != nil {
			return nil, err
		}
	}
	return []*sbom.NodeList{nl}, nil
}

// extractIndex handles a multi-arch image index: each platform image is
// squashed and extracted concurrently, and the results are assembled under
// a node describing the index — index node → (contains) → one node per arch
// image → (contains) → its system packages.
func (u *Unpacker) extractIndex(ctx context.Context, refStr string, nref name.Reference, idx v1.ImageIndex) (*sbom.NodeList, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading index manifest: %w", err)
	}

	// Collect the platform images, skipping non-runnable entries such as
	// buildx attestation manifests (platform "unknown/unknown").
	var members []*v1.Descriptor
	for i := range manifest.Manifests {
		m := &manifest.Manifests[i]
		if !m.MediaType.IsImage() || isAttestation(m) {
			continue
		}
		members = append(members, m)
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("index %q has no platform images", refStr)
	}

	// Extract every platform image in parallel. Each one is addressed by
	// its digest-pinned reference.
	lists := make([]*sbom.NodeList, len(members))
	g, gctx := errgroup.WithContext(ctx)
	for i, m := range members {
		g.Go(func() error {
			img, err := idx.Image(m.Digest)
			if err != nil {
				return fmt.Errorf("reading platform image %s: %w", m.Digest, err)
			}
			archRef := nref.Context().Name() + "@" + m.Digest.String()
			archNref, err := name.ParseReference(archRef)
			if err != nil {
				return fmt.Errorf("building platform reference: %w", err)
			}
			nl, err := u.extractImage(gctx, archRef, archNref, img)
			if err != nil {
				return fmt.Errorf("extracting %s: %w", platformString(m.Platform), err)
			}
			lists[i] = nl
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	digest, err := idx.Digest()
	if err != nil {
		return nil, fmt.Errorf("reading index digest: %w", err)
	}

	nl := sbom.NewNodeList()
	node := imageNode(refStr, nref, digest, "", "")
	node.Description = "multi-arch image index"
	nl.AddRootNode(node)
	for _, archList := range lists {
		if err := nl.RelateNodeListAtID(archList, node.GetId(), sbom.Edge_contains); err != nil {
			return nil, fmt.Errorf("relating platform image to index node: %w", err)
		}
	}
	return nl, nil
}

// isAttestation reports whether an index entry is a buildx attestation
// manifest rather than a runnable platform image.
func isAttestation(desc *v1.Descriptor) bool {
	if desc.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
		return true
	}
	return desc.Platform != nil &&
		desc.Platform.OS == "unknown" && desc.Platform.Architecture == "unknown"
}

// platformString renders a platform for error messages, tolerating nil.
func platformString(p *v1.Platform) string {
	if p == nil {
		return "unknown platform"
	}
	return p.String()
}

// remoteOptions assembles the go-containerregistry options used for all
// registry operations: the caller's context and the ambient credentials
// (docker config et al.).
func (u *Unpacker) remoteOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(fallbackKeychain{inner: authn.DefaultKeychain}),
	}
}

// fallbackKeychain resolves credentials through the wrapped keychain but
// degrades to anonymous access when resolution itself fails — for example
// when a docker credential helper is configured but broken (expired gcloud
// login, missing helper binary). Most images we unpack are public, and a
// broken helper should not prevent reading them; genuinely private images
// then fail with the registry's own authorization error instead.
type fallbackKeychain struct {
	inner authn.Keychain
}

func (k fallbackKeychain) Resolve(r authn.Resource) (authn.Authenticator, error) {
	auth, err := k.inner.Resolve(r)
	if err != nil {
		//nolint:nilerr // swallowing the error is this type's purpose: degrade to anonymous
		return authn.Anonymous, nil
	}
	return auth, nil
}

// extractImage squashes a single-arch image and returns a NodeList rooted
// at a node describing the image, with the system packages found in the
// filesystem related to it as descendants.
func (u *Unpacker) extractImage(ctx context.Context, refStr string, nref name.Reference, img v1.Image) (*sbom.NodeList, error) {
	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("reading image digest: %w", err)
	}
	var arch, osName string
	if cfg, err := img.ConfigFile(); err == nil && cfg != nil {
		arch, osName = cfg.Architecture, cfg.OS
	}

	fsys, cleanup, err := squashToFS(ctx, img, u.Options.Hooks)
	if err != nil {
		return nil, fmt.Errorf("squashing image filesystem: %w", err)
	}
	defer cleanup() //nolint:errcheck // best-effort temp cleanup

	pkgLists, err := u.extractSystemPackages(ctx, fsys)
	if err != nil {
		return nil, err
	}

	nl := sbom.NewNodeList()
	node := imageNode(refStr, nref, digest, arch, osName)
	nl.AddRootNode(node)
	for _, pkgs := range pkgLists {
		if err := nl.RelateNodeListAtID(pkgs, node.GetId(), sbom.Edge_contains); err != nil {
			return nil, fmt.Errorf("relating packages to image node: %w", err)
		}
	}
	if u.Options.RecordLayers {
		if err := recordLayers(nl, node, img); err != nil {
			return nil, err
		}
	}
	return nl, nil
}

// recordLayers adds the image's layers to the node list as structural
// nodes hanging off the image node, in layer order, each carrying its
// diff id as name and hash.
func recordLayers(nl *sbom.NodeList, image *sbom.Node, img v1.Image) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("reading image layers: %w", err)
	}
	layerList := sbom.NewNodeList()
	for _, layer := range layers {
		diffID, err := layer.DiffID()
		if err != nil {
			return fmt.Errorf("reading layer diff id: %w", err)
		}
		node := &sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    diffID.String(),
			Comment: "container image layer",
		}
		if algo := hashAlgorithm(diffID.Algorithm); algo != sbom.HashAlgorithm_UNKNOWN {
			node.Hashes = map[int32]string{int32(algo): diffID.Hex}
		}
		layerList.AddRootNode(node)
	}
	if err := nl.RelateNodeListAtID(layerList, image.GetId(), sbom.Edge_contains); err != nil {
		return fmt.Errorf("relating layers to image node: %w", err)
	}
	return nil
}

// extractSystemPackages routes the squashed filesystem to the SystemPackages
// unpacker through the registry, passing down the files option.
func (u *Unpacker) extractSystemPackages(ctx context.Context, fsys fs.FS) ([]*sbom.NodeList, error) {
	subject := &system.Filesystem{FS: fsys}
	unpacker, err := api.UnpackerFor(subject)
	if err != nil {
		return nil, fmt.Errorf("locating system unpacker: %w", err)
	}
	if su, ok := unpacker.(*system.Unpacker); ok {
		su.Options.IncludeFiles = u.Options.IncludeFiles
	}

	lists, err := unpacker.Extract(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("extracting system packages: %w", err)
	}
	return lists, nil
}

// imageNode builds the node describing a single-arch image: the reference
// as the name, the manifest digest in the hashes, and a pkg:oci purl.
func imageNode(refStr string, nref name.Reference, digest v1.Hash, arch, osName string) *sbom.Node {
	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           refStr,
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_CONTAINER},
	}
	// Untagged archive images have no reference to derive a purl or a
	// version from; their name is the image digest.
	if nref != nil {
		node.Identifiers = map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): ociPurl(nref, digest, arch),
		}
		if tag, ok := nref.(name.Tag); ok {
			node.Version = tag.TagStr()
		}
	}
	if algo := hashAlgorithm(digest.Algorithm); algo != sbom.HashAlgorithm_UNKNOWN {
		node.Hashes = map[int32]string{int32(algo): digest.Hex}
	}
	if osName != "" {
		// Record the platform on the node for human consumption; the purl
		// carries the arch qualifier for machines.
		node.Description = osName + "/" + arch
	}
	return node
}

// ociPurl builds a pkg:oci purl per the purl-spec oci definition: the name
// is the last path component of the repository, the version is the manifest
// digest, and qualifiers carry the arch, repository URL and tag.
//
//	pkg:oci/debian@sha256%3A244fd47e07d1...?repository_url=index.docker.io%2Flibrary%2Fdebian&tag=latest
func ociPurl(nref name.Reference, digest v1.Hash, arch string) string {
	repo := nref.Context()

	var b strings.Builder
	b.WriteString("pkg:oci/")
	b.WriteString(strings.ToLower(path.Base(repo.RepositoryStr())))
	b.WriteByte('@')
	// The digest is the purl version; its colon must be percent-encoded.
	b.WriteString(strings.ReplaceAll(digest.String(), ":", "%3A"))

	q := url.Values{}
	if arch != "" {
		q.Set("arch", strings.ToLower(arch))
	}
	q.Set("repository_url", repo.Name())
	if tag, ok := nref.(name.Tag); ok {
		q.Set("tag", tag.TagStr())
	}
	b.WriteByte('?')
	b.WriteString(q.Encode())
	return b.String()
}

// hashAlgorithm maps an OCI digest algorithm to protobom's enum.
func hashAlgorithm(algo string) sbom.HashAlgorithm {
	switch strings.ToLower(algo) {
	case "sha256":
		return sbom.HashAlgorithm_SHA256
	case "sha512":
		return sbom.HashAlgorithm_SHA512
	}
	return sbom.HashAlgorithm_UNKNOWN
}

// RegisterDecomposer is a no-op: the image unpacker has no decomposers of
// its own; it delegates to the unpackers of the subjects it discovers
// inside the image.
func (u *Unpacker) RegisterDecomposer(api.Decomposer) {}

// UnregisterDecomposer is a no-op; see RegisterDecomposer.
func (u *Unpacker) UnregisterDecomposer(api.Decomposer) {}

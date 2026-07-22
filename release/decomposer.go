// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/requirements"
)

var _ api.Decomposer = (*Decomposer)(nil)

// NewDecomposer returns a release decomposer with the builtin forge backends
// preregistered. Additional (or replacement) backends can be plugged in with
// RegisterBackend.
func NewDecomposer() *Decomposer {
	return &Decomposer{
		backends: map[string]Backend{
			ForgeGitHub: NewGitHubBackend(),
		},
	}
}

// Decomposer renders a software release into a protobom NodeList. It drives
// the Backend registered for the reference's forge type to fetch the release
// metadata and the data of the published artifacts, then expresses them as a
// graph: one package node for the release with one file node per artifact.
type Decomposer struct {
	backends map[string]Backend
}

// Options is the driver-level options set of the release decomposer, carried
// in the DecomposerOptions driver options bag.
type Options struct {
	// Reference points at the release to decompose.
	Reference *Reference
}

// DefaultOptions returns the driver-level options used when none are set on
// DecomposerOptions.
func (d *Decomposer) DefaultOptions() any { return &Options{} }

// RegisterBackend registers the backend that handles the given forge type.
// Registering a second backend for the same forge replaces the previous one.
func (d *Decomposer) RegisterBackend(forge string, b Backend) {
	d.backends[forge] = b
}

// Requirements returns the decomposer's runtime requirements. Talking to a
// forge always needs the network, so when the options carry a release
// reference this returns a requirement to reach the forge host over https.
func (d *Decomposer) Requirements(opts *api.DecomposerOptions) []api.Requirement {
	ref := d.referenceFromOptions(opts)
	if ref == nil || ref.Host == "" {
		return nil
	}
	return []api.Requirement{
		&requirements.Network{Host: ref.Host, Port: 443, Proto: "tcp"},
	}
}

// Extract satisfies api.Decomposer by reading the release reference from the
// driver options and delegating to ExtractRelease. Callers that have a
// context should call ExtractRelease directly.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	ref := d.referenceFromOptions(opts)
	if ref == nil {
		return nil, errors.New("no release reference set in the decomposer options")
	}
	return d.ExtractRelease(context.Background(), ref, opts)
}

// ExtractRelease fetches the release the reference points to through the
// backend registered for its forge type and returns it as a NodeList.
func (d *Decomposer) ExtractRelease(ctx context.Context, ref *Reference, _ *api.DecomposerOptions) (*sbom.NodeList, error) {
	if ref == nil {
		return nil, errors.New("cannot extract from a nil release reference")
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("validating release reference: %w", err)
	}
	backend, ok := d.backends[ref.Forge]
	if !ok {
		return nil, fmt.Errorf("no backend registered for forge %q", ref.Forge)
	}

	md, err := backend.FetchReleaseMetadata(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("fetching release metadata: %w", err)
	}
	artifacts, err := backend.FetchArtifactData(ctx, ref, md)
	if err != nil {
		return nil, fmt.Errorf("fetching release artifact data: %w", err)
	}
	return d.buildNodeList(ref, md, artifacts)
}

// referenceFromOptions reads the release reference from the driver options
// bag, returning nil when none is set.
func (d *Decomposer) referenceFromOptions(opts *api.DecomposerOptions) *Reference {
	if opts == nil {
		return nil
	}
	if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
		return dOpts.Reference
	}
	return nil
}

// buildNodeList renders the fetched release data into a NodeList: one root
// package node describing the release, with one file node per published
// artifact related to it through a distributionArtifact edge.
func (d *Decomposer) buildNodeList(ref *Reference, md *Metadata, artifacts []*Artifact) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	root := &sbom.Node{
		Id:          uuid.NewString(),
		Type:        sbom.Node_PACKAGE,
		Name:        path.Base(ref.Repo),
		Version:     md.Tag,
		Description: md.Name,
		UrlHome:     md.URL,
	}
	if md.License != "" {
		root.Licenses = []string{md.License}
		root.LicenseConcluded = md.License
	}
	if md.Commit != "" {
		root.Hashes = map[int32]string{
			int32(sbom.HashAlgorithm_SHA1): md.Commit,
		}
	}
	if md.Published != nil {
		root.ReleaseDate = timestamppb.New(*md.Published)
	}
	if purl := releasePurl(ref, md.Tag); purl != "" {
		root.Identifiers = map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl,
		}
	}
	if vcs := vcsReference(ref, md); vcs != nil {
		root.ExternalReferences = append(root.ExternalReferences, vcs)
	}
	nl.AddRootNode(root)

	for _, artifact := range artifacts {
		node := &sbom.Node{
			Id:          uuid.NewString(),
			Type:        sbom.Node_FILE,
			Name:        artifact.Name,
			FileName:    artifact.Name,
			UrlDownload: artifact.DownloadURL,
		}
		if len(artifact.Digests) > 0 {
			node.Hashes = make(map[int32]string, len(artifact.Digests))
			for algo, digest := range artifact.Digests {
				node.Hashes[int32(algo)] = digest
			}
		}
		if vcs := vcsReference(ref, md); vcs != nil {
			node.ExternalReferences = append(node.ExternalReferences, vcs)
		}
		if err := nl.RelateNodeAtID(node, root.GetId(), sbom.Edge_distributionArtifact); err != nil {
			return nil, fmt.Errorf("relating artifact node %q: %w", artifact.Name, err)
		}
	}
	return nl, nil
}

// releasePurl builds the purl identifying the released repository at the
// release tag (e.g. pkg:github/org/repo@v1.0.0). Purls are only defined for
// the public forge instances, so references pointing at self-managed hosts
// get no purl and the empty string is returned.
func releasePurl(ref *Reference, tag string) string {
	if ref.Host == "" || defaultForgeHosts[ref.Forge] != ref.Host {
		return ""
	}
	var purlType string
	switch ref.Forge {
	case ForgeGitHub:
		purlType = packageurl.TypeGithub
	case ForgeGitLab:
		purlType = packageurl.TypeGitlab
	default:
		return ""
	}
	// Purl namespaces and names are case insensitive in the github and gitlab
	// types and canonically lowercased.
	repo := strings.ToLower(ref.Repo)
	return packageurl.NewPackageURL(
		purlType, path.Dir(repo), path.Base(repo), tag, nil, "",
	).ToString()
}

// vcsReference builds the VCS external reference locating the commit the
// release was built from, or nil when the metadata carries no commit. Every
// call returns a fresh struct so that nodes never share pointers.
func vcsReference(ref *Reference, md *Metadata) *sbom.ExternalReference {
	if md.Commit == "" {
		return nil
	}
	repoURL := md.RepoURL
	if repoURL == "" {
		repoURL = ref.RepoURL()
	}
	return &sbom.ExternalReference{
		Url:  "git+" + repoURL + "@" + md.Commit,
		Type: sbom.ExternalReference_VCS,
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA1): md.Commit,
		},
	}
}

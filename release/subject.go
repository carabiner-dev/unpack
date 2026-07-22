// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package release implements the unpacker that decomposes software releases.
// A release is understood as a build from a commit that publishes a number of
// software artifacts on a hosting system (a "forge") such as GitHub or GitLab.
package release

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// SubjectType is the DecomposableSubject type routed to the release unpacker.
const SubjectType = "release"

// Identifiers of the forge types with builtin support.
const (
	ForgeGitHub = "github"
	ForgeGitLab = "gitlab"
)

// defaultForgeHosts maps a forge type to the host of its public instance, used
// when a reference does not name a host explicitly.
var defaultForgeHosts = map[string]string{
	ForgeGitHub: "github.com",
	ForgeGitLab: "gitlab.com",
}

// forgesByHost maps the well-known public forge hosts back to their forge type
// to infer it when parsing pasted URLs.
var forgesByHost = map[string]string{
	"github.com": ForgeGitHub,
	"gitlab.com": ForgeGitLab,
}

// Reference is the DecomposableSubject consumed by the release unpacker. It
// locates one release through three coordinates: the forge type that knows how
// to talk to the hosting system, the host of the (possibly self-managed)
// instance, and the repository the release was published in. An empty Tag
// points the reference at the repository's latest release.
type Reference struct {
	// Forge identifies the hosting system type, e.g. "github" or "gitlab".
	Forge string

	// Host is the hostname of the forge instance, e.g. "github.com" or the
	// domain of a self-managed instance.
	Host string

	// Repo is the repository path in the forge, e.g. "org/repo". GitLab
	// paths may nest subgroups ("group/subgroup/project").
	Repo string

	// Tag is the tag the release was cut from. Empty means the repository's
	// latest release.
	Tag string
}

// DecomposableType identifies this subject as a software release, routing it
// to the release unpacker through the registry.
func (r *Reference) DecomposableType() string { return SubjectType }

// String returns the canonical string form of the reference:
//
//	forge+https://host/repo[@tag]
func (r *Reference) String() string {
	ret := r.Forge + "+https://" + r.Host + "/" + r.Repo
	if r.Tag != "" {
		ret += "@" + r.Tag
	}
	return ret
}

// RepoURL returns the https URL of the repository the release lives in.
func (r *Reference) RepoURL() string {
	return "https://" + r.Host + "/" + r.Repo
}

// Validate checks that the reference coordinates are complete and well formed.
func (r *Reference) Validate() error {
	errs := []error{}
	if r.Forge == "" {
		errs = append(errs, errors.New("reference has no forge type"))
	}
	if r.Host == "" {
		errs = append(errs, errors.New("reference has no forge host"))
	}
	segments := strings.Split(r.Repo, "/")
	switch {
	case r.Repo == "":
		errs = append(errs, errors.New("reference has no repository path"))
	case slices.Contains(segments, ""):
		errs = append(errs, fmt.Errorf("repository path %q has empty segments", r.Repo))
	case len(segments) < 2:
		errs = append(errs, fmt.Errorf("repository path %q needs at least two segments", r.Repo))
	case r.Forge == ForgeGitHub && len(segments) != 2:
		errs = append(errs, fmt.Errorf("github repositories are expected to be org/repo, got %q", r.Repo))
	}
	return errors.Join(errs...)
}

// ParseReference parses a string into a release Reference. Three forms are
// understood:
//
//   - Canonical: "github+https://github.com/org/repo@v1.0.0". The forge type,
//     the instance URL and the repository path are all explicit.
//   - Shorthand: "github:org/repo@v1.0.0". The host defaults to the forge's
//     public instance; name other instances explicitly, as in
//     "github:ghe.example.com/org/repo@v1.0.0". The first path segment is
//     taken as a host when it contains a dot and at least two more segments
//     follow (dotted GitLab namespaces holding nested subgroups need the
//     canonical form).
//   - Release page URL: "https://github.com/org/repo/releases/tag/v1.0.0".
//     The forge type is inferred from the well-known public hosts.
//
// In all forms, omitting "@tag" points the reference at the repository's
// latest release.
func ParseReference(s string) (*Reference, error) {
	s = strings.TrimSpace(s)
	var ref *Reference
	var err error
	switch {
	case s == "":
		return nil, errors.New("empty release reference")
	case strings.HasPrefix(s, "http://"):
		return nil, fmt.Errorf("insecure http URLs are not supported in release reference %q", s)
	case strings.HasPrefix(s, "https://"):
		ref, err = parseReferenceURL(s)
	case strings.Contains(s, "+https://"):
		ref, err = parseCanonicalReference(s)
	default:
		ref, err = parseShorthandReference(s)
	}
	if err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	return ref, nil
}

// parseCanonicalReference parses the explicit "forge+https://host/repo[@tag]"
// reference form.
func parseCanonicalReference(s string) (*Reference, error) {
	forge, rest, _ := strings.Cut(s, "+https://")
	if forge == "" || strings.ContainsAny(forge, ":/@") {
		return nil, fmt.Errorf("invalid forge type in release reference %q", s)
	}
	locator, tag, err := cutTag(s, rest)
	if err != nil {
		return nil, err
	}
	host, repo, ok := strings.Cut(locator, "/")
	if !ok {
		return nil, fmt.Errorf("release reference %q has no repository path", s)
	}
	return &Reference{Forge: forge, Host: host, Repo: repo, Tag: tag}, nil
}

// parseShorthandReference parses the "forge:[host/]repo[@tag]" reference form,
// defaulting the host to the forge's public instance when not named.
func parseShorthandReference(s string) (*Reference, error) {
	forge, rest, ok := strings.Cut(s, ":")
	if !ok {
		return nil, fmt.Errorf("release reference %q has no forge type prefix", s)
	}
	if forge == "" || strings.ContainsAny(forge, "/@.") {
		return nil, fmt.Errorf("invalid forge type in release reference %q", s)
	}
	locator, tag, err := cutTag(s, rest)
	if err != nil {
		return nil, err
	}
	segments := strings.Split(locator, "/")
	if strings.Contains(segments[0], ".") && len(segments) >= 3 {
		return &Reference{
			Forge: forge,
			Host:  segments[0],
			Repo:  strings.Join(segments[1:], "/"),
			Tag:   tag,
		}, nil
	}
	host, ok := defaultForgeHosts[forge]
	if !ok {
		return nil, fmt.Errorf(
			"no default host known for forge %q, name the instance host in the reference", forge,
		)
	}
	return &Reference{Forge: forge, Host: host, Repo: locator, Tag: tag}, nil
}

// parseReferenceURL parses a pasted https URL pointing to a release page or a
// repository on one of the well-known public forge hosts.
func parseReferenceURL(s string) (*Reference, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parsing release reference URL: %w", err)
	}
	forge, ok := forgesByHost[u.Host]
	if !ok {
		return nil, fmt.Errorf(
			"cannot infer the forge type from host %q, use the forge+https:// reference form", u.Host,
		)
	}
	// Work on the escaped path so that tags with encoded slashes survive.
	urlPath := strings.Trim(u.EscapedPath(), "/")
	ref := &Reference{Forge: forge, Host: u.Host}

	// The release tag is the path remainder after each forge's release
	// prefix; without it the URL points at the repository (latest release).
	tagSeparator := "/releases/tag/"
	latestSuffix := "/releases/latest"
	if forge == ForgeGitLab {
		tagSeparator = "/-/releases/"
		latestSuffix = "/-/releases/permalink/latest"
	}
	urlPath = strings.TrimSuffix(urlPath, latestSuffix)
	if repo, escapedTag, found := strings.Cut(urlPath, tagSeparator); found {
		tag, err := url.PathUnescape(escapedTag)
		if err != nil {
			return nil, fmt.Errorf("unescaping release tag: %w", err)
		}
		ref.Repo = repo
		ref.Tag = tag
		return ref, nil
	}
	ref.Repo = strings.TrimSuffix(urlPath, "/releases")
	ref.Repo = strings.TrimSuffix(ref.Repo, "/-")
	return ref, nil
}

// cutTag splits a locator from its optional "@tag" suffix. The repository
// paths of the supported forges cannot contain "@", so everything after the
// first one (including any further "@") belongs to the tag.
func cutTag(ref, locator string) (path, tag string, err error) {
	path, tag, found := strings.Cut(locator, "@")
	if found && tag == "" {
		return "", "", fmt.Errorf("empty tag in release reference %q", ref)
	}
	return path, tag, nil
}

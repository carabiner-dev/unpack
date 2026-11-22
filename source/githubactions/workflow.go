// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package githubactions

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file reads what a GitHub Actions workflow runs that is not the
// repository's own: the actions its steps use, the workflows its jobs
// call, and the container images its jobs and services run in.

// Kinds of a reference.
const (
	// KindAction is an action a step uses: owner/repo[/path]@ref.
	KindAction = "action"

	// KindWorkflow is a reusable workflow a job calls:
	// owner/repo/.github/workflows/file.yml@ref.
	KindWorkflow = "reusable-workflow"

	// KindImage is a container image: of a docker:// action, of a job's
	// container, or of a service.
	KindImage = "image"
)

// Reference is one thing a workflow runs from elsewhere.
type Reference struct {
	Kind string

	// Raw is the reference as the workflow writes it.
	Raw string

	// For an action or a workflow: the repository, the path of the
	// action inside it when it is not at its root, and the ref it is
	// used at, a tag, a branch or a commit.
	Owner string
	Repo  string
	Path  string
	Ref   string

	// Comment is the comment on the line of the reference, without its
	// marker. A reference pinned to a commit by convention says there
	// which version the commit is: "v4.1.1".
	Comment string

	// For an image: its repository as written (ghcr.io/owner/image,
	// node), its tag and its digest.
	Image  string
	Tag    string
	Digest string

	// Line is the line of the workflow the reference is on.
	Line int
}

// Pinned says whether a reference names exactly one content: an action
// or workflow at a full commit, an image by digest. A tag or a branch can
// be moved.
func (r *Reference) Pinned() bool {
	if r.Kind == KindImage {
		return r.Digest != ""
	}
	return fullCommit.MatchString(r.Ref)
}

var (
	fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

	// expression is what GitHub evaluates when the workflow runs:
	// ${{ matrix.image }}.
	expression = "${{"
)

// ReadWorkflow reads the references of a workflow file.
func ReadWorkflow(path string) ([]*Reference, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading workflow: %w", err)
	}
	return ParseWorkflow(data)
}

// ParseWorkflow reads the references of a workflow:
//
//	jobs.<id>.uses                       a reusable workflow
//	jobs.<id>.steps[].uses               an action, or a docker:// image
//	jobs.<id>.container[.image]          the image a job runs in
//	jobs.<id>.services.<id>[.image]      the image of a service
//
// A reference to something of the repository itself (./path) names
// nothing from elsewhere and is left out, and so is one that is an
// expression, whose value is only known when the workflow runs.
func ParseWorkflow(data []byte) ([]*Reference, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parsing workflow: %w", err)
	}
	if len(document.Content) == 0 {
		return nil, nil
	}

	references := []*Reference{}
	add := func(reference *Reference) {
		if reference != nil {
			references = append(references, reference)
		}
	}

	jobs := child(document.Content[0], "jobs")
	for _, job := range values(jobs) {
		if uses := child(job, "uses"); uses != nil {
			add(usesReference(uses, KindWorkflow))
		}
		add(imageNode(child(job, "container")))
		for _, service := range values(child(job, "services")) {
			add(imageNode(service))
		}
		steps := child(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if uses := child(step, "uses"); uses != nil {
				add(usesReference(uses, KindAction))
			}
		}
	}
	return references, nil
}

// child returns the value of a key of a mapping, and nil for anything
// that has none. An alias is followed to what it names.
func child(node *yaml.Node, key string) *yaml.Node {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return resolve(node.Content[i+1])
		}
	}
	return nil
}

// values returns the values of a mapping.
func values(node *yaml.Node) []*yaml.Node {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(node.Content)/2)
	for i := 1; i < len(node.Content); i += 2 {
		out = append(out, resolve(node.Content[i]))
	}
	return out
}

func resolve(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

func comment(node *yaml.Node) string {
	return strings.TrimSpace(strings.TrimLeft(node.LineComment, "#"))
}

// usesReference reads the value of a uses key.
func usesReference(node *yaml.Node, kind string) *Reference {
	if node.Kind != yaml.ScalarNode {
		return nil
	}
	raw := strings.TrimSpace(node.Value)
	switch {
	case raw == "" || strings.Contains(raw, expression):
		return nil
	case strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../"):
		// An action or a workflow of the repository itself.
		return nil
	case strings.HasPrefix(raw, "docker://"):
		reference := imageReference(strings.TrimPrefix(raw, "docker://"))
		if reference != nil {
			reference.Raw, reference.Line, reference.Comment = raw, node.Line, comment(node)
		}
		return reference
	}

	location, ref, found := strings.Cut(raw, "@")
	parts := strings.Split(location, "/")
	if !found || ref == "" || len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	return &Reference{
		Kind: kind, Raw: raw, Line: node.Line, Comment: comment(node),
		Owner: parts[0], Repo: parts[1], Path: strings.Join(parts[2:], "/"), Ref: ref,
	}
}

// imageNode reads an image where a workflow may write it as a string or
// as a mapping with an image key.
func imageNode(node *yaml.Node) *Reference {
	node = resolve(node)
	if node == nil {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		node = child(node, "image")
		if node == nil {
			return nil
		}
	}
	if node.Kind != yaml.ScalarNode {
		return nil
	}
	raw := strings.TrimSpace(node.Value)
	reference := imageReference(raw)
	if reference != nil {
		reference.Raw, reference.Line, reference.Comment = raw, node.Line, comment(node)
	}
	return reference
}

// imageReference takes an image reference apart: a repository, then a
// tag after a colon and a digest after an at sign, either of which may
// be missing. The colon of a registry's port is not a tag's.
func imageReference(raw string) *Reference {
	if raw == "" || strings.Contains(raw, expression) {
		return nil
	}
	reference := &Reference{Kind: KindImage}
	rest, digest, _ := strings.Cut(raw, "@")
	reference.Digest = digest
	if colon := strings.LastIndex(rest, ":"); colon > strings.LastIndex(rest, "/") {
		rest, reference.Tag = rest[:colon], rest[colon+1:]
	}
	if rest == "" {
		return nil
	}
	reference.Image = rest
	return reference
}

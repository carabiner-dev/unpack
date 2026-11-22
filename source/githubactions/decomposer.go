// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package githubactions reads what the GitHub Actions workflows of a
// repository run from elsewhere: actions, reusable workflows and
// container images.
package githubactions

import (
	"context"
	"fmt"
	"os"
	"path"
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
)

var (
	_ api.Decomposer        = (*Decomposer)(nil)
	_ api.SourceDecomposer  = (*Decomposer)(nil)
	_ api.ContextDecomposer = (*Decomposer)(nil)
	_ api.ContextReporter   = (*Decomposer)(nil)
)

// Properties a node carries.
const (
	// PropertyKind is what the reference is: action, reusable-workflow
	// or image.
	PropertyKind = "githubactions:kind"

	// PropertyPinned says whether the reference names exactly one
	// content: "true" for an action or workflow at a full commit and an
	// image by digest, "false" for a tag or a branch, which can be
	// moved.
	PropertyPinned = "githubactions:pinned"

	// PropertyComment is the comment on the line of the reference. By
	// convention it says which version a commit is ("v4.1.1"); it is
	// what a person wrote, and nothing checks it.
	PropertyComment = "githubactions:comment"

	// PropertyUsedIn is a place the reference is used, as file:line,
	// once for each.
	PropertyUsedIn = "githubactions:used-in"
)

// workflowsDir is where a repository keeps its workflows.
const workflowsDir = ".github/workflows"

// New returns a ready-to-use GitHub Actions decomposer.
func New() *Decomposer { return &Decomposer{} }

// Decomposer reads dependency data from GitHub Actions workflows.
type Decomposer struct{}

// DefaultOptions returns nothing: the decomposer takes no driver options.
func (d *Decomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: the workflows are read in Go, and GitHub
// is not asked anything.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// GenerationContext says in what context the decomposer's data is read:
// the workflow files, as they stand in the source tree.
func (d *Decomposer) GenerationContext() api.GenerationContext { return api.ContextSource }

func isWorkflowFile(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

// FindCodeBases locates repositories with workflows: the directories that
// hold a .github/workflows with a YAML file in it. The codebase is the
// repository, not the directory of the workflows.
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	found := []string{}
	for dir, files := range *index {
		slashed := filepath.ToSlash(filepath.Clean(dir))
		if slashed != workflowsDir && !strings.HasSuffix(slashed, "/"+workflowsDir) {
			continue
		}
		if slices.ContainsFunc(files, isWorkflowFile) {
			found = append(found, filepath.Dir(filepath.Dir(filepath.Clean(dir))))
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

// ExtractWithContext reads the workflows of a repository and returns what
// they run from elsewhere, each a build dependency of the repository.
//
// They are build dependencies whatever the inclusion flags say: running
// this decomposer is asking for them, and there is nothing else it
// reads.
func (d *Decomposer) ExtractWithContext(ctx context.Context, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "."
	}
	log := logging.FromContext(ctx)

	dir := filepath.Join(workDir, filepath.FromSlash(workflowsDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading workflows: %w", err)
	}

	nl := sbom.NewNodeList()
	root := rootNode(workDir, opts)
	nl.AddRootNode(root)

	nodes := map[string]*sbom.Node{}
	// record adds the references read from a file to the graph.
	record := func(file string, references []*Reference) error {
		for _, reference := range references {
			key := reference.Kind + " " + reference.Raw
			node, known := nodes[key]
			if !known {
				node = referenceNode(reference)
				nodes[key] = node
				if err := nl.RelateNodeAtID(node, root.GetId(), sbom.Edge_buildDependency); err != nil {
					return fmt.Errorf("relating %s: %w", reference.Raw, err)
				}
			}
			addProperty(node, PropertyUsedIn, fmt.Sprintf("%s:%d", file, reference.Line))
			addProperty(node, PropertyComment, reference.Comment)
		}
		return nil
	}

	// The repository's own actions the workflows use, to read in turn.
	pending := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !isWorkflowFile(entry.Name()) {
			continue
		}
		file := workflowsDir + "/" + entry.Name()
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading workflow: %w", err)
		}
		references, local, err := parseWorkflow(data)
		if err != nil {
			// One workflow that is not YAML is no reason to lose the
			// others.
			log.Warn("githubactions: a workflow cannot be read and is left out", "workflow", file, "error", err)
			continue
		}
		if err := record(file, references); err != nil {
			return nil, err
		}
		pending = append(pending, local...)
	}

	// A local action is code of the repository, and names nothing from
	// elsewhere itself. What it uses does: a composite action runs steps
	// like a workflow's, and may use other local actions in turn.
	visited := map[string]bool{}
	for len(pending) > 0 {
		action := localActionPath(pending[0])
		pending = pending[1:]
		if action == "" || visited[action] {
			continue
		}
		visited[action] = true

		file, data := readActionFile(workDir, action)
		if data == nil {
			log.Debug("githubactions: a local action has no metadata file to read", "action", action)
			continue
		}
		references, local, err := ParseAction(data)
		if err != nil {
			log.Warn("githubactions: a local action cannot be read and is left out", "action", file, "error", err)
			continue
		}
		if err := record(file, references); err != nil {
			return nil, err
		}
		pending = append(pending, local...)
	}
	return nl, nil
}

// localActionPath turns the path a step writes for an action of the
// repository, ./path, into one relative to the repository, and returns
// nothing for a path that leaves it.
func localActionPath(raw string) string {
	cleaned := path.Clean(strings.TrimPrefix(strings.TrimSpace(raw), "./"))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return ""
	}
	return cleaned
}

// readActionFile reads the metadata file of an action of the repository,
// and returns its path relative to the repository with its contents, or
// nothing when the action has none.
func readActionFile(workDir, action string) (file string, data []byte) {
	for _, name := range ActionFiles {
		file = path.Join(action, name)
		data, err := os.ReadFile(filepath.Join(workDir, filepath.FromSlash(file)))
		if err == nil {
			return file, data
		}
	}
	return "", nil
}

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

func rootNode(workDir string, opts *api.DecomposerOptions) *sbom.Node {
	name := filepath.Base(workDir)
	if abs, err := filepath.Abs(workDir); err == nil {
		name = filepath.Base(abs)
	}
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: opts.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeGeneric, "", name, opts.Version, nil, "").ToString(),
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

// referenceNode renders a reference.
func referenceNode(reference *Reference) *sbom.Node {
	if reference.Kind == KindImage {
		return imageNodeOf(reference)
	}

	// An action or a workflow is a path of a repository on GitHub at a
	// ref: the repository names it, and the path is the purl's subpath.
	name := reference.Owner + "/" + reference.Repo
	if reference.Path != "" {
		name += "/" + reference.Path
	}
	repository := "https://github.com/" + reference.Owner + "/" + reference.Repo
	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: reference.Ref,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeGithub, strings.ToLower(reference.Owner), strings.ToLower(reference.Repo),
				reference.Ref, nil, reference.Path).ToString(),
		},
		// Who controls the repository, which is all a reference says
		// of who the action is from.
		Suppliers: []*sbom.Person{{
			Name: reference.Owner, Url: "https://github.com/" + reference.Owner, IsOrg: true,
		}},
	}
	vcs := &sbom.ExternalReference{Url: repository, Type: sbom.ExternalReference_VCS}
	if reference.Pinned() {
		vcs.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA1): reference.Ref}
	}
	node.ExternalReferences = []*sbom.ExternalReference{vcs}

	addProperty(node, PropertyKind, reference.Kind)
	addProperty(node, PropertyPinned, fmt.Sprintf("%t", reference.Pinned()))
	return node
}

// imageNodeOf renders a container image: versioned by its digest when it
// has one, which names its content, and by its tag otherwise.
func imageNodeOf(reference *Reference) *sbom.Node {
	parts := strings.Split(reference.Image, "/")
	registry := ""
	// A first element with a dot or a port is a registry's host.
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		registry, parts = parts[0], parts[1:]
	}
	namespace := strings.Join(parts[:len(parts)-1], "/")
	name := parts[len(parts)-1]

	version := reference.Tag
	qualifiers := map[string]string{}
	if reference.Digest != "" {
		version = reference.Digest
		if reference.Tag != "" {
			qualifiers["tag"] = reference.Tag
		}
	}
	if registry != "" {
		qualifiers["repository_url"] = registry
	}
	keys := make([]string, 0, len(qualifiers))
	for key := range qualifiers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sorted := make(purl.Qualifiers, 0, len(keys))
	for _, key := range keys {
		sorted = append(sorted, purl.Qualifier{Key: key, Value: qualifiers[key]})
	}

	node := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    reference.Image,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl.NewPackageURL(
				purl.TypeDocker, namespace, name, version, sorted, "").ToString(),
		},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_CONTAINER},
	}
	if algorithm, value, found := strings.Cut(reference.Digest, ":"); found && algorithm == "sha256" {
		node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): value}
	}
	addProperty(node, PropertyKind, reference.Kind)
	addProperty(node, PropertyPinned, fmt.Sprintf("%t", reference.Pinned()))
	return node
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// This file reads requirements.txt, the format that predates lockfiles.
// What it yields depends on how the file was made. A compiled file
// (pip-compile, uv pip compile) is as good as a lock: exact pins, hashes,
// and "# via" annotations recording which requirement pulled in which — a
// real tree. A hand-written file declares constraints: entries without an
// exact pin become nodes without a version, and entries without provenance
// hang off the root. The reader takes what each line actually says and
// invents nothing.

// requirementEntry is one requirement plus what the file says about it.
type requirementEntry struct {
	requirement

	// Hashes are the sha256 values of the entry's --hash options. The
	// file does not say which artifact each belongs to, so only a lone
	// hash identifies the content.
	Hashes []string

	// Via lists what pulled this entry in, from the "# via" annotations
	// compiled files carry: requirement names, or "-r file" for a direct
	// requirement. The annotation is either on the lines below the entry
	// or at the end of its own line, depending on how the file was
	// compiled. Empty when the file has no annotations.
	Via []string
}

// readRequirementsFile reads a requirements file and the files it includes.
func readRequirementsFile(path string, visited map[string]bool) ([]*requirementEntry, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if visited[abs] {
		return nil, nil
	}
	visited[abs] = true

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading requirements: %w", err)
	}

	entries := []*requirementEntry{}

	// annotated is the entry of this file a via annotation would belong
	// to, the one right above it, and listing says the annotation is in
	// its list form, each parent on a comment line of its own.
	var annotated *requirementEntry
	listing := false

	for _, line := range logicalLines(string(data)) {
		if strings.HasPrefix(line, "#") {
			// A via annotation belongs to the entry above it. Any other
			// comment is the author's, or the compiler's header, and
			// names nothing.
			if annotated != nil {
				var names []string
				names, listing = viaNames(line, listing)
				annotated.Via = append(annotated.Via, names...)
			}
			continue
		}
		annotated, listing = nil, false

		switch {
		case strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement "):
			_, include, _ := strings.Cut(line, " ")
			included, err := readRequirementsFile(
				filepath.Join(filepath.Dir(path), strings.TrimSpace(include)), visited)
			if err != nil {
				return nil, err
			}
			entries = append(entries, included...)
		case strings.HasPrefix(line, "-"):
			// Editables point at local trees with no version to state, and
			// the rest are installer options: index URLs, constraints
			// files, binary policies. None of them declare a package.
			continue
		case bareReference(line):
			// TODO(degradation): pip also accepts bare paths and URLs —
			// ./vendor/pkg, https://host/pkg.whl — which name no package.
			// They are skipped rather than guessed at, and rather than
			// failing the file they are legal lines of.
			continue
		default:
			entry, err := parseRequirementLine(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
			}
			entries = append(entries, entry)
			annotated = entry
		}
	}
	return entries, nil
}

// bareReference says whether a line is a path or URL rather than a named
// requirement. A requirement's name cannot contain a slash, so a first
// field holding one is a reference to content, not a declaration of a
// package.
func bareReference(line string) bool {
	first := strings.Fields(line)[0]
	return strings.Contains(first, "/") || first == "." || strings.HasPrefix(first, "~")
}

// logicalLines joins the physical lines the file continues with a trailing
// backslash, and trims what remains.
func logicalLines(data string) []string {
	lines := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(data, "\\\n", " "), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// viaNames reads the parents out of one comment line under an entry.
// Compiled files write the annotation in two forms: "# via flask" names
// one parent on the line, and a bare "# via" opens a list, each parent on
// a comment line of its own below it, set in from the "#" the way the
// compilers write it: "#   flask". listing says whether such a list is
// open, and the second return value whether it is after this line.
//
// A comment that is neither names nothing, and closes the list: one the
// author wrote under it, "# pinned for the release", is told from an item
// by sitting right after its "#".
func viaNames(line string, listing bool) (names []string, stillListing bool) {
	text := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	switch {
	case text == "via":
		return nil, true
	case strings.HasPrefix(text, "via "):
		return []string{strings.TrimSpace(strings.TrimPrefix(text, "via "))}, false
	case listing && text != "" && strings.HasPrefix(line, viaListIndent):
		return []string{text}, true
	default:
		return nil, false
	}
}

// viaListIndent opens an item of a via list: the comment mark and at least
// two spaces. pip-compile and uv write three.
const viaListIndent = "#  "

// inlineComment matches the comment a line ends with. As pip reads it, a
// "#" opens a comment only after whitespace, which leaves the fragment of
// a URL ("...#egg=name") alone.
var inlineComment = regexp.MustCompile(`\s+#.*$`)

// inlineVia reads the parents out of the comment a requirement line ends
// with. pip-compile's line annotation style writes the whole annotation
// there, parents separated by commas: "# via -r requirements.in, flask".
// Any other comment is the author's and names nothing.
func inlineVia(comment string) []string {
	text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(comment), "#"))
	list, found := strings.CutPrefix(text, "via ")
	if !found {
		return nil
	}
	names := []string{}
	for _, name := range strings.Split(list, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// parseRequirementLine reads one requirement with its per-line options
// and the comment it may end with.
func parseRequirementLine(line string) (*requirementEntry, error) {
	entry := &requirementEntry{}

	// The comment goes first: left in place it would be read as part of
	// the version, and the entry would lose its pin.
	if loc := inlineComment.FindStringIndex(line); loc != nil {
		entry.Via = inlineVia(line[loc[0]:])
		line = line[:loc[0]]
	}
	spec := line

	if i := strings.Index(line, "--hash="); i >= 0 {
		spec = line[:i]
		for _, field := range strings.Fields(line[i:]) {
			if value, ok := strings.CutPrefix(field, "--hash=sha256:"); ok {
				entry.Hashes = append(entry.Hashes, value)
			}
		}
	}

	req, err := parseRequirement(strings.TrimSpace(spec))
	if err != nil {
		return nil, err
	}
	entry.requirement = *req
	return entry, nil
}

// extractRequirements builds the graph a requirements.txt states.
func (d *Decomposer) extractRequirements(workDir string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	entries, err := readRequirementsFile(filepath.Join(workDir, "requirements.txt"), map[string]bool{})
	if err != nil {
		return nil, err
	}

	dOpts := d.getOptions(opts)
	env, err := d.environment(dOpts, opts, fallbackPythonVersion)
	if err != nil {
		return nil, err
	}

	nl := sbom.NewNodeList()
	root := requirementsRoot(workDir, opts)
	nl.AddRootNode(root)

	// First what is in this environment: one entry per name, the first
	// whose marker holds. Two entries of one name survive marker
	// filtering only in a hand-written file repeating itself.
	declared := map[string]bool{}
	selected := map[string]*requirementEntry{}
	order := []*requirementEntry{}
	for _, entry := range entries {
		declared[entry.Name] = true
		holds, err := env.Evaluate(entry.Marker)
		if err != nil {
			return nil, fmt.Errorf("evaluating marker on %s: %w", entry.Name, err)
		}
		if !holds {
			continue
		}
		if _, seen := selected[entry.Name]; seen {
			continue
		}
		selected[entry.Name] = entry
		order = append(order, entry)
	}

	// An entry every parent of which is left out of this environment is
	// left out with them: nothing here pulls it in. Dropping one may
	// orphan another, so this repeats until it settles.
	for dropped := true; dropped; {
		dropped = false
		for _, entry := range order {
			if _, in := selected[entry.Name]; !in {
				continue
			}
			if parents := classifyVia(entry, declared, selected); parents.orphaned() {
				delete(selected, entry.Name)
				dropped = true
			}
		}
	}

	// Then the nodes.
	nodes := map[packageKey]*sbom.Node{}
	byName := map[string]*sbom.Node{}
	enrichable := map[packageKey]bool{}
	for _, entry := range order {
		if _, in := selected[entry.Name]; !in {
			continue
		}
		node := requirementNode(entry)
		nodes[packageKey{name: entry.Name, version: entry.Version}] = node
		byName[entry.Name] = node
		nl.AddNode(node)
		if entry.Version != "" && entry.URL == "" {
			enrichable[packageKey{name: entry.Name, version: entry.Version}] = true
		}
	}

	// Then the edges. A via annotation hangs the entry under each package
	// that pulled it in, and off the root as well when the project itself
	// did; an entry with no annotation hangs off the root.
	for _, entry := range order {
		node, ok := byName[entry.Name]
		if !ok {
			continue
		}
		parents := classifyVia(entry, declared, selected)
		for _, name := range parents.packages {
			if err := nl.RelateNodeAtID(node, byName[name].GetId(), sbom.Edge_dependsOn); err != nil {
				return nil, err
			}
		}
		if parents.direct || len(parents.packages) == 0 {
			if err := nl.RelateNodeAtID(node, root.GetId(), sbom.Edge_dependsOn); err != nil {
				return nil, err
			}
		}
	}

	if opts.Networking >= api.NetworkEssential {
		NewPyPIClient(dOpts.Concurrency).enrichNodes(nodes, enrichable)
	}
	return nl, nil
}

// viaParents is what an entry's via annotations say pulled it in.
type viaParents struct {
	// direct is set when the project itself requires the entry: there is
	// no annotation, or one names a requirements file or the project's
	// manifest, or a name the file does not declare at all, which can
	// only stand for the project.
	direct bool

	// packages are the entries of this environment that require it.
	packages []string

	// absent counts the parents the file declares for other
	// environments.
	absent int
}

// orphaned says the entry has parents, and none of them in this
// environment.
func (p viaParents) orphaned() bool {
	return !p.direct && len(p.packages) == 0 && p.absent > 0
}

// classifyVia sorts an entry's via annotations by what they name. declared
// holds every name the file has an entry for, selected the entries that
// are in this environment.
func classifyVia(entry *requirementEntry, declared map[string]bool, selected map[string]*requirementEntry) viaParents {
	parents := viaParents{direct: len(entry.Via) == 0}
	for _, via := range entry.Via {
		switch {
		case strings.HasPrefix(via, "-c ") || strings.HasPrefix(via, "--constraint "):
			// A constraints file narrows the version and requires
			// nothing.
			continue
		case strings.HasPrefix(via, "-") || strings.Contains(via, "("):
			// "-r requirements.in", or "project (pyproject.toml)".
			parents.direct = true
			continue
		}

		name := NormalizeName(via)
		switch {
		case name == entry.Name:
			continue
		case !declared[name]:
			parents.direct = true
		case selected[name] != nil:
			parents.packages = append(parents.packages, name)
		default:
			parents.absent++
		}
	}
	return parents
}

// requirementsRoot builds the root node. The format names no project, so
// the directory has to lend its name; the caller may know the version.
func requirementsRoot(workDir string, opts *api.DecomposerOptions) *sbom.Node {
	abs, err := filepath.Abs(workDir)
	if err != nil {
		abs = workDir
	}
	name := NormalizeName(filepath.Base(abs))

	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           name,
		Version:        opts.Version,
		Identifiers:    map[int32]string{},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	purlValue := "pkg:pypi/" + name
	if opts.Version != "" {
		purlValue = purl(name, opts.Version)
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlValue

	if opts.CommitHash != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): opts.CommitHash},
			Type:   sbom.ExternalReference_VCS,
		})
	}
	return node
}

// requirementNode builds the node one entry states.
func requirementNode(entry *requirementEntry) *sbom.Node {
	node := &sbom.Node{
		Id:             uuid.NewString(),
		Type:           sbom.Node_PACKAGE,
		Name:           entry.Name,
		Version:        entry.Version,
		Identifiers:    map[int32]string{},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	// An unpinned entry has no version to put in a purl: a range is a
	// constraint on a resolver, not a version.
	purlValue := "pkg:pypi/" + entry.Name
	if entry.Version != "" {
		purlValue = purl(entry.Name, entry.Version)
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purlValue

	if entry.URL != "" {
		node.UrlDownload = entry.URL
		if strings.HasPrefix(entry.URL, "git+") {
			node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
				Url:  entry.URL,
				Type: sbom.ExternalReference_VCS,
			})
		}
	}

	// The file does not say which artifact each hash belongs to, so only
	// a lone hash identifies this entry's content. A compiled file lists
	// every artifact's hash, and picking one would be guessing.
	if len(entry.Hashes) == 1 {
		node.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): entry.Hashes[0]}
	}
	return node
}

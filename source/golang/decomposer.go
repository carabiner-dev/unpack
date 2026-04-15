// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

var _ api.Decomposer = (*Decomposer)(nil)

const (
	defaultProxyURL    = "https://proxy.golang.org"
	defaultConcurrency = 10
	defaultHTTPTimeout = 10 * time.Second
)

func New() *Decomposer {
	return &Decomposer{}
}

type Decomposer struct{}

// Options configures the Go dependency extraction
type Options struct {
	IncludeGo   bool
	ProxyURL    string       // default: https://proxy.golang.org
	HTTPClient  *http.Client // allow HTTP custom client for testing
	Concurrency int          // number of parallel HTTP requests (default: 10)
}

var defaultOptions = Options{
	IncludeGo:   true,
	ProxyURL:    defaultProxyURL,
	Concurrency: defaultConcurrency,
}

func (d *Decomposer) DefaultOptions() any {
	return defaultOptions
}

// Requirements returns the requirements for the decomposer.
// No external binary required - uses pure Go implementation.
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement {
	return nil
}

// Extract parses the local go.mod file, fetches dependency information from
// the Go module proxy, and builds the complete dependency graph as a protobom NodeList.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	// Get decomposer-specific options
	dOpts := d.getOptions(opts)

	// 1. Parse local go.mod
	goModPath := filepath.Join(opts.WorkDir, "go.mod")
	modFile, err := d.parseLocalGoMod(goModPath)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	// 2. Build dependency tree by fetching go.mod files from the proxy
	trees, err := d.buildDependencyTree(modFile, goModPath, dOpts)
	if err != nil {
		return nil, fmt.Errorf("building dependency tree: %w", err)
	}

	// 3. Convert to NodeList
	root := modFile.Module.Mod.Path
	var goVersion string
	if modFile.Go != nil {
		goVersion = modFile.Go.Version
	}
	nl, err := d.convertTrees(opts, root, trees, goVersion)
	if err != nil {
		return nil, fmt.Errorf("converting graph trees: %w", err)
	}

	return nl, nil
}

// getOptions extracts Go-specific options from DecomposerOptions
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
	if opts != nil {
		if dOpts, ok := opts.GetDriverOptions(d).(*Options); ok {
			return dOpts
		}
	}
	return &defaultOptions
}

// parseLocalGoMod reads and parses a go.mod file from the local filesystem
func (d *Decomposer) parseLocalGoMod(path string) (*modfile.File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	modFile, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	return modFile, nil
}

// parseGoSum reads and parses a go.sum file into a map of module@version -> []hashes
func (d *Decomposer) parseGoSum(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading go.sum: %w", err)
	}

	hashes := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: module version hash
		// e.g., golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		modPath := parts[0]
		version := parts[1]
		hash := parts[2]

		// Strip /go.mod suffix from version if present
		version = strings.TrimSuffix(version, "/go.mod")

		key := fmt.Sprintf("%s@%s", modPath, version)
		hashes[key] = append(hashes[key], hash)
	}

	return hashes, scanner.Err()
}

// replaceTarget holds the replacement module path and version
type replaceTarget struct {
	Path    string
	Version string
}

// buildDependencyTree builds the dependency tree by:
// 1. First, reading all resolved dependencies from go.mod and go.sum (the "resolved set")
// 2. Fetching go.mod files for each dependency from the proxy
// 3. Building edges only between modules in the resolved set\
//
//nolint:gocritic,unparam
func (d *Decomposer) buildDependencyTree(root *modfile.File, goModPath string, opts *Options) (*map[string][]string, error) {
	trees := make(map[string][]string)

	// Build replace directive map
	replaces := make(map[string]replaceTarget)
	for _, r := range root.Replace {
		if r.New.Path != "" && !isLocalReplace(r.New.Path) {
			replaces[r.Old.Path] = replaceTarget{Path: r.New.Path, Version: r.New.Version}
			if r.Old.Version != "" {
				replaces[fmt.Sprintf("%s@%s", r.Old.Path, r.Old.Version)] = replaceTarget{Path: r.New.Path, Version: r.New.Version}
			}
		}
	}

	// Build exclude set
	excludes := make(map[string]struct{})
	for _, e := range root.Exclude {
		excludes[fmt.Sprintf("%s@%s", e.Mod.Path, e.Mod.Version)] = struct{}{}
	}

	// Build the resolved set: all modules from go.mod with their resolved versions
	// Key: module@version, Value: true if direct dependency
	resolvedSet := make(map[string]bool)
	rootKey := root.Module.Mod.Path

	for _, req := range root.Require {
		modPath, version := d.resolveModule(req.Mod.Path, req.Mod.Version, replaces)

		// Check if excluded
		if _, excluded := excludes[fmt.Sprintf("%s@%s", modPath, version)]; excluded {
			continue
		}

		depKey := fmt.Sprintf("%s@%s", modPath, version)
		resolvedSet[depKey] = !req.Indirect
		trees[rootKey] = append(trees[rootKey], depKey)
	}

	// Also parse go.sum to get all transitive dependencies
	// These are needed to build the complete dependency graph
	goSumPath := strings.TrimSuffix(goModPath, ".mod") + ".sum"
	if sumHashes, err := d.parseGoSum(goSumPath); err == nil {
		for modKey := range sumHashes {
			// Don't overwrite direct dependencies already in the set
			if _, exists := resolvedSet[modKey]; !exists {
				// Check if excluded
				if _, excluded := excludes[modKey]; !excluded {
					resolvedSet[modKey] = false // mark as indirect
				}
			}
		}
	}

	// Fetch go.mod files for all modules in the resolved set to get their dependencies
	d.fetchDependencyGraph(trees, resolvedSet, replaces, opts)

	return &trees, nil
}

// fetchDependencyGraph fetches go.mod files for all modules in the resolved set
// and builds edges between them. Only creates edges to modules that are also in
// the resolved set (avoiding the exponential explosion of fetching all transitive deps).
func (d *Decomposer) fetchDependencyGraph(
	trees map[string][]string, resolvedSet map[string]bool,
	replaces map[string]replaceTarget, opts *Options,
) {
	// Get list of modules to fetch
	toFetch := make([]string, 0, len(resolvedSet))
	for modKey := range resolvedSet {
		toFetch = append(toFetch, modKey)
	}

	if len(toFetch) == 0 {
		return
	}

	// Build a map from module path > resolved module@version
	// This lets us match dependencies by path and use the resolved version
	pathToResolved := make(map[string]string)
	for modKey := range resolvedSet {
		modPath, _, ok := strings.Cut(modKey, "@")
		if ok {
			pathToResolved[modPath] = modKey
		}
	}

	// Set up concurrency
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	// Use WaitGroup and semaphore for parallel fetching
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex // protects trees map

	// Create HTTP client with timeout
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}

	proxyURL := opts.ProxyURL
	if proxyURL == "" {
		proxyURL = defaultProxyURL
	}

	for _, modKey := range toFetch {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore

		go func(modKey string) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore

			modPath, version, ok := strings.Cut(modKey, "@")
			if !ok {
				return
			}

			// Skip local replaces
			if isLocalReplace(modPath) {
				return
			}

			// Fetch the module's go.mod
			modFile, err := d.fetchModFile(modPath, version, proxyURL, client)
			if err != nil {
				// Skip - some modules may not have go.mod or may be unreachable
				return
			}

			// Find dependencies that are in our resolved set (by module path)
			var deps []string
			for _, req := range modFile.Require {
				depPath, _ := d.resolveModule(req.Mod.Path, req.Mod.Version, replaces)

				// Look up by module path and use the resolved version
				if resolvedKey, inSet := pathToResolved[depPath]; inSet {
					deps = append(deps, resolvedKey)
				}
			}

			if len(deps) > 0 {
				mu.Lock()
				trees[modKey] = append(trees[modKey], deps...)
				mu.Unlock()
			}
		}(modKey)
	}

	wg.Wait()
}

// fetchModFile fetches a go.mod file from the Go module proxy
func (d *Decomposer) fetchModFile(modPath, version, proxyURL string, client *http.Client) (*modfile.File, error) {
	// Escape module path for URL
	escapedPath, err := module.EscapePath(modPath)
	if err != nil {
		return nil, fmt.Errorf("escaping module path %q: %w", modPath, err)
	}

	url := fmt.Sprintf("%s/%s/@v/%s.mod", proxyURL, escapedPath, version)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Parse with ParseLax for older modules
	cacheKey := fmt.Sprintf("%s@%s", modPath, version)
	modFile, err := modfile.ParseLax(cacheKey+"/go.mod", body, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod for %s: %w", cacheKey, err)
	}

	return modFile, nil
}

// resolveModule resolves a module path and version considering replace directives
func (d *Decomposer) resolveModule(path, version string, replaces map[string]replaceTarget) (rpath, rversion string) {
	// Check for version-specific replace first
	key := fmt.Sprintf("%s@%s", path, version)
	if repl, ok := replaces[key]; ok {
		if repl.Path != "" {
			return repl.Path, repl.Version
		}
		return path, repl.Version
	}

	// Check for module-level replace
	if repl, ok := replaces[path]; ok {
		if repl.Path != "" {
			return repl.Path, repl.Version
		}
		return path, repl.Version
	}

	return path, version
}

// isLocalReplace checks if a path is a local replace (relative or absolute path)
func isLocalReplace(path string) bool {
	return strings.HasPrefix(path, "./") ||
		strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, "/")
}

// convertTrees reads the tree map parsed from the go graph output and
// converts it to a protobom NodeList, capturing the graph structure.
func (d *Decomposer) convertTrees(
	opts *api.DecomposerOptions, root string, trees *map[string][]string, goVersion string, //nolint:gocritic
) (nl *sbom.NodeList, err error) {
	// Create the new NodeList
	nl = sbom.NewNodeList()

	// Add the root package to anchor the
	// module's dependencies
	rootNode := &sbom.Node{
		Id:      uuid.NewString(),
		Type:    sbom.Node_PACKAGE,
		Name:    root,
		Version: opts.Version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): goStringToPurl(root),
		},
	}
	nl.AddRootNode(rootNode)

	// Run the recursive tree converter
	if err = d.convertTree(nl, []string{root}, trees, &map[string]struct{}{}); err != nil {
		return nil, fmt.Errorf("error running recursive conversion: %w", err)
	}

	// If the options specify a new version, set it here. Not before traversing
	// the tree because recursion breaks:
	if opts.Version != "" {
		rootNode.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = goStringToPurl(fmt.Sprintf("%s@%s", root, opts.Version))
	}

	// Add the Go stdlib as a dependency, using the Go version declared in go.mod
	if goVersion != "" {
		stdlibPurl := fmt.Sprintf("pkg:golang/stdlib@%s", goVersion)
		stdlibNode := &sbom.Node{
			Id:      uuid.NewString(),
			Type:    sbom.Node_PACKAGE,
			Name:    "stdlib",
			Version: goVersion,
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): stdlibPurl,
			},
			Licenses: []string{"BSD-3-Clause"},
			PrimaryPurpose: []sbom.Purpose{
				sbom.Purpose_LIBRARY,
			},
		}
		if err := nl.RelateNodeAtID(stdlibNode, rootNode.GetId(), sbom.Edge_dependsOn); err != nil {
			return nil, fmt.Errorf("relating stdlib node: %w", err)
		}
	}

	if opts.CommitHash != "" {
		rootNode.ExternalReferences = append(rootNode.ExternalReferences, &sbom.ExternalReference{
			Hashes: map[int32]string{
				int32(sbom.HashAlgorithm_SHA1): opts.CommitHash,
			},
			Type: sbom.ExternalReference_VCS,
		})
	}

	return nl, nil
}

// convertTree takes a nodelist and a component entry. It expects the component
// to already be expressed as a node in the protobom nodelist (from its ancestor).
//
// The function returns the list of the components' descendants to keep recursing.
// An empty list means the component is a leaf and no more recursion is needed.
func (d *Decomposer) convertTree(
	nl *sbom.NodeList, components []string, trees *map[string][]string, seen *map[string]struct{}, //nolint:gocritic
) error {
	// Cycle all the components
	for _, component := range components {
		if _, ok := (*seen)[component]; ok {
			continue
		}

		// All components should already exist in the protobom
		// nodelist from a previous iteration
		nodes := nl.GetNodesByIdentifier("purl", goStringToPurl(component))
		if len(nodes) == 0 {
			return fmt.Errorf("unable to find existing node for %s", goStringToPurl(component))
		}

		// If the component does not have an entry in the tree catalog
		// it means that it does not have any dependencies. Iterate to the next.
		if _, ok := (*trees)[component]; !ok {
			continue
		}

		// Process each of the component's dependencies:
		for _, subcomponent := range (*trees)[component] {
			name, version, ok := strings.Cut(subcomponent, "@")
			if !ok {
				return fmt.Errorf("unable to parse go graph entry: %q", subcomponent)
			}

			subComponentNodes := nl.GetNodesByIdentifier("purl", goStringToPurl(subcomponent))

			var node *sbom.Node
			if len(subComponentNodes) > 0 {
				node = subComponentNodes[0]
			} else {
				node = &sbom.Node{
					Id:          uuid.NewString(),
					Type:        sbom.Node_PACKAGE,
					Name:        name,
					Version:     version,
					UrlDownload: fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip", name, version),
					Licenses:    []string{},
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): goStringToPurl(subcomponent),
					},
					Hashes: map[int32]string{},
					PrimaryPurpose: []sbom.Purpose{
						sbom.Purpose_LIBRARY,
					},
				}
			}

			// Add the node
			if err := nl.RelateNodeAtID(node, nodes[0].GetId(), sbom.Edge_dependsOn); err != nil {
				return fmt.Errorf("error relating node: %w", err)
			}
		}

		(*seen)[component] = struct{}{}
		// Recurse to the subcomponent's children
		if err := d.convertTree(nl, (*trees)[component], trees, seen); err != nil {
			return err
		}
	}
	return nil
}

// goStringToPurl converts a graph entry to a package url
func goStringToPurl(gostring string) string {
	name, version, ok := strings.Cut(gostring, "@")
	purl := fmt.Sprintf("pkg:golang/%s", name)
	if ok {
		purl = fmt.Sprintf("%s@%s", purl, version)
	}
	return purl
}

func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
	return index.FindFileLocations("go.mod")
}

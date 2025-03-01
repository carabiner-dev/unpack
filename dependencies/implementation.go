// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
	"github.com/carabiner-dev/unpack/filesystem"
	"github.com/carabiner-dev/unpack/internal/git"
	"github.com/protobom/protobom/pkg/sbom"
	"sigs.k8s.io/release-utils/util"
)

type unpackerImplementation interface {
	// IndexPaths constructs an index of the code directories for easy
	// lookup of recognized files by decomposers
	IndexPaths(context.Context, *Options, Sources) (map[string]*code.PathIndex, error)

	// ScanPaths runs the indexed filesystems through the configured decomposers
	// to extract codebases, that is directories containing source code that
	// a decomposer can use to extract dependencies
	ScanPaths(context.Context, *Options, map[string]api.Decomposer, map[string]*code.PathIndex) (map[api.Decomposer][]string, error)

	// ExtractCodeBases runs the found codebases throuhg the decomposers and returns
	// the resulting nodelists.
	ExtractCodeBases(context.Context, *Options, map[api.Decomposer][]string) ([]*sbom.NodeList, error)
}

type defaultImplementation struct{}

func (di *defaultImplementation) IndexPaths(
	ctx context.Context, opts *Options, src Sources,
) (map[string]*code.PathIndex, error) {
	indexer := code.Indexer{}
	ret := map[string]*code.PathIndex{}
	if src.Paths == nil {
		return ret, nil
	}
	for _, path := range src.Paths {
		idx, err := indexer.CatalogDirectories(path)
		if err != nil {
			return nil, fmt.Errorf("indexing %q: %w", path, err)
		}
		ret[path] = idx
	}
	return ret, nil
}

// ScanPaths analyuses paths and returns a set of locations where codebases were
// found.
func (di *defaultImplementation) ScanPaths(
	ctx context.Context, opts *Options,
	decomposers map[string]api.Decomposer, indices map[string]*code.PathIndex,
) (map[api.Decomposer][]string, error) {
	ret := map[api.Decomposer][]string{}
	for _, d := range decomposers {
		if sd, ok := d.(api.SourceDecomposer); ok {
			for path, idx := range indices {
				locations, err := sd.FindCodeBases(idx)
				if err != nil {
					return nil, fmt.Errorf("finding codebases in %q: %w", path, err)
				}
				if len(locations) == 0 {
					continue
				}
				ret[d] = locations
			}
		}
	}
	return ret, nil
}

func (di *defaultImplementation) ExtractCodeBases(
	ctx context.Context, opts *Options, codebaseMap map[api.Decomposer][]string,
) ([]*sbom.NodeList, error) {
	ret := []*sbom.NodeList{}
	for d, codebases := range codebaseMap {
		for _, cbPath := range codebases {
			// If this is a git repo, compute the version from the tag data
			var ver, hashHex string
			if opts.ReadGitVersion && util.IsDir(filepath.Join(cbPath, ".git")) {
				var err error
				ver, hashHex, err = git.RepoVersion(filepath.Join(cbPath, ".git"))
				if err != nil {
					return nil, fmt.Errorf("reading version from repo: %w", err)
				}
			}

			nl, err := d.Extract(&api.DecomposerOptions{
				WorkDir:    cbPath,
				Version:    ver,
				CommitHash: hashHex,
			})
			if err != nil {
				return nil, fmt.Errorf("from %q with %T: %w", cbPath, d, err)
			}

			// This should never happen but we need it to
			// prevent a panic below
			if len(nl.RootElements) == 0 {
				return nil, fmt.Errorf("no root element found on resulting nodelist")
			}

			// Index the source files if the options is set
			if opts.IndexFiles {
				opts.logger.Debug(fmt.Sprintf("indexing all files in %s", cbPath))
				fsd, err := filesystem.New()
				if err != nil {
					return nil, fmt.Errorf("creating fs decomposer: %w", err)
				}

				nlFiles, err := fsd.IndexFS(os.DirFS(cbPath))
				if err != nil {
					return nil, fmt.Errorf("indexing filesystem: %w", err)
				}

				opts.logger.Debug(fmt.Sprintf("read data from %d files", len(nlFiles.RootElements)))

				// Mix the resulting nodes into the code nodelist
				err = nl.RelateNodeListAtID(nlFiles, nl.RootElements[0], sbom.Edge_contains)
				if err != nil {
					return nil, fmt.Errorf("adding file nodes: %w", err)
				}
			}
			ret = append(ret, nl)
		}
	}
	return ret, nil
}

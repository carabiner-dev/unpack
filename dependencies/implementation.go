// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"context"
	"fmt"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
	"github.com/protobom/protobom/pkg/sbom"
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

// ScanPaths
func (di *defaultImplementation) ScanPaths(ctx context.Context, opts *Options, decomposers map[string]api.Decomposer, indices map[string]*code.PathIndex) (map[api.Decomposer][]string, error) {
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

func (di *defaultImplementation) ExtractCodeBases(ctx context.Context, opts *Options, codebaseMap map[api.Decomposer][]string) ([]*sbom.NodeList, error) {
	ret := []*sbom.NodeList{}
	for d, codebases := range codebaseMap {
		for _, cbPath := range codebases {
			nl, err := d.Extract(&api.DecomposerOptions{
				WorkDir: cbPath,
			})
			if err != nil {
				return nil, fmt.Errorf("extracting dependencies from %q with %T", cbPath, d)
			}
			ret = append(ret, nl)
		}
	}
	return ret, nil
}

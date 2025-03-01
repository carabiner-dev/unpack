// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"context"
	"fmt"
	"log/slog"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/golang"
	"github.com/carabiner-dev/unpack/source/rust"
	"github.com/protobom/protobom/pkg/sbom"
)

func NewUnpacker() *Unpacker {
	return &Unpacker{
		Options: DefaultOptions,
		impl:    &defaultImplementation{},
		decomposers: map[string]api.Decomposer{
			"rust":   rust.New(),
			"golang": golang.New(),
		},
	}
}

type Options struct {
	// FailOnSingleMulti makes Unpacker return an error on calls that return a
	// single nodelist but obtain more than one from the configured decomposers.
	// This can happen when a directory contains code for more than one language
	// or multiple projects in the same directory.
	//
	// By default this is on as turning it off causes unpacker to behave in a
	// non-deterministic way as it can return diferent data depending on the
	// order of the configured decomposers
	FailOnSingleMulti bool

	// IndexFiles instructs the unpacker to add all files to the resulting
	// nodelist after running source decomposers in a directory. This runs
	// the file decomposer indexer which will hash all files in the source
	// directory.
	IndexFiles bool

	// ReadGitVersion instructs the unpacker to read the current version from
	// the git history and pass it to the decomposers to use as the version
	// for the root nodes.
	ReadGitVersion bool

	logger *slog.Logger
}

var DefaultOptions = Options{
	FailOnSingleMulti: true,
	ReadGitVersion:    true,
	logger:            slog.Default(),
}

type Sources struct {
	Paths     []string
	Artifacts []string
}

// Unpacker is the main tool to extract dependency data
type Unpacker struct {
	Options     Options
	impl        unpackerImplementation
	decomposers map[string]api.Decomposer
}

// Extract is an alias of ExtractWithContext without context support
func (unpacker *Unpacker) Extract(sources Sources) ([]*sbom.NodeList, error) {
	return unpacker.ExtractWithContext(context.Background(), sources)
}

// ExtractWithContext launches the analyzers in the configured sources and returns
// resulting nodelists.
func (unpacker *Unpacker) ExtractWithContext(ctx context.Context, sources Sources) ([]*sbom.NodeList, error) {
	// Index the specified directories
	codeIndices, err := unpacker.impl.IndexPaths(ctx, &unpacker.Options, sources)
	if err != nil {
		return nil, fmt.Errorf("indexing codebases: %w", err)
	}

	codebases, err := unpacker.impl.ScanPaths(ctx, &unpacker.Options, unpacker.decomposers, codeIndices)
	if err != nil {
		return nil, fmt.Errorf("scaning for codebases: %w", err)
	}

	nodelists, err := unpacker.impl.ExtractCodeBases(ctx, &unpacker.Options, codebases)
	if err != nil {
		return nil, fmt.Errorf("extracting data from codebases: %w", err)
	}

	// Extract from the codebases
	return nodelists, nil
}

// ExtractFromCodeBaseWithContext
func (unpacker *Unpacker) ExtractCodebase(path string) (*sbom.NodeList, error) {
	return unpacker.ExtractCodebaseWithContext(context.Background(), path)
}

// ExtractCodeBaseWithContext extracts data from a single directory.
func (unpacker *Unpacker) ExtractCodebaseWithContext(ctx context.Context, path string) (*sbom.NodeList, error) {
	nodelists, err := unpacker.ExtractWithContext(ctx, Sources{
		Paths: []string{path},
	})
	if err != nil {
		return nil, fmt.Errorf("extracting codebases: %w", err)
	}

	switch len(nodelists) {
	case 0:
		return nil, nil
	case 1:
		return nodelists[0], nil
	default:
		// Fail if FailOnSingleMulti is set:
		if unpacker.Options.FailOnSingleMulti {
			return nil, fmt.Errorf("multiple codebases found in %q", path)
		}

		unpacker.Options.logger.WarnContext(
			ctx, fmt.Sprintf("%d codebases found, only returning the first", len(nodelists)),
		)
		return nodelists[0], nil
	}
}

// ExtractFromCodeBaseWithContext
func (unpacker *Unpacker) ExtractArtifact(path string) (*sbom.NodeList, error) {
	return unpacker.ExtractCodebaseWithContext(context.Background(), path)
}

// ExtractCodeBaseWithContext extracts data from a single directory.
func (unpacker *Unpacker) ExtractArtifactWithContext(ctx context.Context, path string) (*sbom.NodeList, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (unpacker *Unpacker) RegisterDecomposer(d api.Decomposer) {
	unpacker.decomposers[fmt.Sprintf("%T", d)] = d
}

func (unpacker *Unpacker) UnregisterDecomposer(d api.Decomposer) {
	delete(unpacker.decomposers, fmt.Sprintf("%T", d))
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/golang"
	"github.com/carabiner-dev/unpack/source/maven"
	"github.com/carabiner-dev/unpack/source/npm"
	"github.com/carabiner-dev/unpack/source/rust"
)

var ErrMultipleCodebases = errors.New("multiple codebases found")

func NewUnpacker() *Unpacker {
	return &Unpacker{
		Options: DefaultOptions,
		impl:    &defaultImplementation{},
		decomposers: map[string]api.Decomposer{
			"rust":   rust.New(),
			"golang": golang.New(),
			"npm":    npm.New(),
			"maven":  maven.New(),
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
	// non-deterministic way as it can return different data depending on the
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

	// IgnorePatterns are additional paths to ignore (in addition to thise in .gitignore)
	IgnorePatterns []string

	// UseGitIgnore instructs the unpacker to use load patterns from the gitignore
	// file when available .
	UseGitIgnore bool

	// CodebaseFilter filters to a specific codebase by ID (e.g., "golang:./services/api").
	// If empty, all codebases are included.
	CodebaseFilter string

	logger *slog.Logger
}

var DefaultOptions = Options{
	FailOnSingleMulti: true,
	ReadGitVersion:    true,
	UseGitIgnore:      true,
	IndexFiles:        false,
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

	// Apply codebase filter if specified
	if unpacker.Options.CodebaseFilter != "" {
		codebases, err = unpacker.filterCodebases(codebases, sources.Paths)
		if err != nil {
			return nil, fmt.Errorf("filtering codebases: %w", err)
		}
	}

	nodelists, err := unpacker.impl.ExtractCodeBases(ctx, &unpacker.Options, codebases)
	if err != nil {
		return nil, fmt.Errorf("extracting data from codebases: %w", err)
	}

	// Extract from the codebases
	return nodelists, nil
}

// filterCodebases filters the codebase map to only include the codebase matching the filter ID.
func (unpacker *Unpacker) filterCodebases(codebases map[api.Decomposer][]string, basePaths []string) (map[api.Decomposer][]string, error) {
	filterLang, filterPath, err := ParseCodebaseID(unpacker.Options.CodebaseFilter)
	if err != nil {
		return nil, fmt.Errorf("parsing codebase filter: %w", err)
	}

	// Build reverse lookup from decomposer to language name
	decomposerToLanguage := make(map[api.Decomposer]string)
	for lang, d := range unpacker.decomposers {
		decomposerToLanguage[d] = lang
	}

	// Determine the base path for relative path calculations
	basePath := "."
	if len(basePaths) > 0 {
		basePath = basePaths[0]
	}

	filtered := make(map[api.Decomposer][]string)
	found := false

	for decomposer, paths := range codebases {
		language := decomposerToLanguage[decomposer]
		if language != filterLang {
			continue
		}

		for _, absPath := range paths {
			relPath, err := unpacker.impl.RelativePath(basePath, absPath)
			if err != nil {
				return nil, fmt.Errorf("computing relative path: %w", err)
			}

			if relPath == filterPath {
				filtered[decomposer] = []string{absPath}
				found = true
				break
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("codebase %q not found", unpacker.Options.CodebaseFilter)
	}

	return filtered, nil
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
			return nil, ErrMultipleCodebases
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

// ListCodebases discovers and lists all codebases found in the given path.
func (unpacker *Unpacker) ListCodebases(ctx context.Context, path string) ([]CodebaseInfo, error) {
	// Index the specified path
	codeIndices, err := unpacker.impl.IndexPaths(ctx, &unpacker.Options, Sources{
		Paths: []string{path},
	})
	if err != nil {
		return nil, fmt.Errorf("indexing path: %w", err)
	}

	// Scan for codebases
	codebaseMap, err := unpacker.impl.ScanPaths(ctx, &unpacker.Options, unpacker.decomposers, codeIndices)
	if err != nil {
		return nil, fmt.Errorf("scanning for codebases: %w", err)
	}

	// Build reverse lookup from decomposer to language name
	decomposerToLanguage := make(map[api.Decomposer]string)
	for lang, d := range unpacker.decomposers {
		decomposerToLanguage[d] = lang
	}

	// Convert to CodebaseInfo list
	var result []CodebaseInfo
	for decomposer, paths := range codebaseMap {
		language := decomposerToLanguage[decomposer]
		for _, absPath := range paths {
			// Calculate relative path
			relPath, err := unpacker.impl.RelativePath(path, absPath)
			if err != nil {
				return nil, fmt.Errorf("computing relative path: %w", err)
			}

			result = append(result, CodebaseInfo{
				ID:       GenerateCodebaseID(language, relPath),
				Language: language,
				Path:     relPath,
				AbsPath:  absPath,
			})
		}
	}

	return result, nil
}

// ExtractFromCodeBaseWithContext
func (unpacker *Unpacker) ExtractSBOMFromFile(path string) (*sbom.NodeList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	return unpacker.ExtractSBOM(context.Background(), f)
}

// ExtractFromCodeBaseWithContext
func (unpacker *Unpacker) ExtractSBOM(ctx context.Context, r io.ReadSeeker) (*sbom.NodeList, error) {
	return unpacker.impl.ExtractSBOM(ctx, r)
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/sirupsen/logrus"
)

const gitIgnoreFile = ".gitignore"

// PathIndex lists all directories with their files
type PathIndex map[string][]string

// Adds an entry to the filesystem
func (pi PathIndex) Add(dirname, filename string) {
	if _, ok := pi[dirname]; !ok {
		pi[dirname] = []string{}
	}
	pi[dirname] = append(pi[dirname], filename)
}

// FindFileLocations searches the index for directories containing a file
// matching a specific name.
func (pi PathIndex) FindFileLocations(filename string) ([]string, error) {
	ret := []string{}
	for dir, files := range pi {
		if slices.Contains(files, filename) {
			ret = append(ret, dir)
		}
	}

	return ret, nil
}

type Indexer struct {
	options indexerOptions
}
type indexerOptions struct {
	// Load patterns from gitignore
	UseGitIgnore bool

	// Additional gitignore patterns to consider
	ExtraIgnorePatterns []string
}

type optFn func(*indexerOptions)

func WithExtraIgnorePattners(patterns []string) optFn {
	return func(io *indexerOptions) {
		io.ExtraIgnorePatterns = patterns
	}
}

func WithUseGitignore(sino bool) optFn {
	return func(io *indexerOptions) {
		io.UseGitIgnore = sino
	}
}

// CatalogFiles traverses a filesystem and returns an index of all directories
// with their files
func (i *Indexer) CatalogDirectories(path string, funcs ...optFn) (*PathIndex, error) {
	for _, f := range funcs {
		f(&i.options)
	}

	patterns, err := i.ignorePatterns(path)
	if err != nil {
		return nil, fmt.Errorf("building patterns: %w", err)
	}

	var matcher gitignore.Matcher

	if len(patterns) > 0 {
		// Build the new gitignore matcher
		matcher = gitignore.NewMatcher(patterns)
	} else {
		fmt.Printf("No hay patterns\n")
	}

	index := PathIndex{}
	if err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		// Si if the path matches the pattern
		if matcher != nil && matcher.Match(strings.Split(path, string(filepath.Separator)), false) {
			return nil
		}
		index.Add(filepath.Dir(path), d.Name())
		return nil
	}); err != nil {
		return nil, err
	}
	return &index, nil
}

// ignorePatterns compiles the list of gitignore patterns from options and
// from the gitignore file.
func (i *Indexer) ignorePatterns(dirPath string) ([]gitignore.Pattern, error) {
	patterns := []gitignore.Pattern{}
	for _, s := range i.options.ExtraIgnorePatterns {
		patterns = append(patterns, gitignore.ParsePattern(s, nil))
	}

	if i.options.UseGitIgnore {
		// Open the gitignore file, if we fail dont err. Simply ignore.
		f, err := os.Open(filepath.Join(dirPath, gitIgnoreFile))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return patterns, nil
			}
			return nil, fmt.Errorf("opening gitignore file: %w", err)
		}
		defer f.Close() //nolint:errcheck

		// When using .gitignore files, we alwas add the .git directory
		// to match git's behavior
		patterns = append(patterns, gitignore.ParsePattern(".git/", nil))

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			s := scanner.Text()
			if !strings.HasPrefix(s, "#") && strings.TrimSpace(s) != "" {
				logrus.Debugf("Loaded .gitignore pattern: >>%s<<", s)
				patterns = append(patterns, gitignore.ParsePattern(s, nil))
			}
		}
	}

	logrus.Debugf(
		"Loaded %d patterns from .gitignore (%d from options extra) ",
		len(patterns), len(i.options.ExtraIgnorePatterns),
	)
	return patterns, nil
}

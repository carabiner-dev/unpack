// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"io/fs"
	"path/filepath"
	"slices"
)

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
}

// CatalogFiles traverses a filesystem and returns an index of all directories
// with their files
func (i *Indexer) CatalogDirectories(path string) (*PathIndex, error) {
	index := PathIndex{}
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		index.Add(filepath.Dir(path), d.Name())
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &index, nil
}

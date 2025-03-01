// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gitignore "github.com/go-git/go-git/v5/plumbing/format/gitignore"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/nozzle/throttler"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/hasher"

	api "github.com/carabiner-dev/unpack/api/v1"
)

const gitIgnoreFile = ".gitignore"

func New(funcs ...optFn) (*Decomposer, error) {
	opts := defaultOptions
	for _, f := range funcs {
		f(&opts)
	}

	h := hasher.New()
	return &Decomposer{
		Hasher:  h,
		Options: opts,
	}, nil
}

// Decomposer is a filesystem indexer
type Decomposer struct {
	Hasher  *hasher.Hasher
	Options Options
}

// Extract reads and hashes the files from the filesystem
func (d *Decomposer) Extract(*api.DecomposerOptions) (*sbom.NodeList, error) {
	nl, err := d.IndexFS(d.Options.Filesystem)
	if err != nil {
		return nil, fmt.Errorf("indexing filesystem: %w", err)
	}
	return nl, nil
}

// IndexFS takes an fs.FS and returns a nodelist with all the files indexed
// and hashed.
func (d *Decomposer) IndexFS(source fs.FS) (*sbom.NodeList, error) {
	// dirPath, err = filepath.Abs(dirPath)
	// if err != nil {
	// 	return nil, fmt.Errorf("getting absolute directory path: %w", err)
	// }

	// Always reset the hashes before running
	d.Hasher.Options.Algorithms = d.Options.Algorithms

	// First, get a list of all the files
	fileList, err := d.readtTree(source)
	if err != nil {
		return nil, fmt.Errorf("building directory tree: %w", err)
	}

	// Build a list of patterns from those found in the .gitignore file and
	// posssibly others passed in the options:
	patterns, err := d.ignorePatterns(source, ".")
	if err != nil {
		return nil, fmt.Errorf("building ignore patterns list: %w", err)
	}

	// Apply the ignore patterns to the list of files
	fileList = d.applyIgnorePatterns(fileList, patterns)
	if len(fileList) == 0 {
		return nil, fmt.Errorf("filesystem has no files to scan")
	}

	logrus.Debugf("Scanning %d files", len(fileList))

	t := throttler.New(5, len(fileList))
	var mtx = sync.Mutex{}

	var nl = sbom.NewNodeList()

	// Read the files in parallel
	for _, path := range fileList {
		go func() {
			node, err := d.processFile(source, path)
			if err != nil {
				t.Done(err)
				return
			}

			mtx.Lock()
			nl.AddNode(node)
			mtx.Unlock()

			t.Done(nil)
		}()
		t.Throttle()
	}

	// If the throttler picked an error, fail here
	if err := t.Err(); err != nil {
		return nil, err
	}

	// Add files into the package
	return nl, nil
}

func (d *Decomposer) readtTree(source fs.FS) ([]string, error) {
	fileList := []string{}

	if err := fs.WalkDir(source, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if d.Type() == os.ModeSymlink {
			return nil
		}

		fileList = append(fileList, path)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("building directory tree: %w", err)
	}
	return fileList, nil
}

// func (d *Decomposer) ReadLicense() {
// 	reader, err := di.LicenseReader(opts)
// 	if err != nil {
// 		return nil, fmt.Errorf("creating license reader: %w", err)
// 	}

// 	licenseTag := ""
// 	lic, err := di.GetDirectoryLicense(reader, dirPath, opts)
// 	if err != nil {
// 		return nil, fmt.Errorf("scanning directory for licenses: %w", err)
// 	}
// 	if lic != nil {
// 		licenseTag = lic.LicenseID
// 	}
// }

// ignorePatterns compiles the list of gitignore patterns from options and
// from the gitignore file
func (d *Decomposer) ignorePatterns(source fs.FS, dirPath string) ([]gitignore.Pattern, error) {
	patterns := []gitignore.Pattern{}
	for _, s := range d.Options.IgnorePatterns {
		patterns = append(patterns, gitignore.ParsePattern(s, nil))
	}

	if d.Options.NoGitignore {
		logrus.Debug("Not using patterns in .gitignore")
		return patterns, nil
	}
	fmt.Println("Sale de " + filepath.Join(dirPath, gitIgnoreFile))

	f, err := source.Open(filepath.Join(dirPath, gitIgnoreFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return patterns, nil
		}
		return nil, fmt.Errorf("opening gitignore file: %w", err)
	}
	defer f.Close()

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

	logrus.Debugf(
		"Loaded %d patterns from .gitignore (%d from options extra) ",
		len(patterns), len(d.Options.IgnorePatterns),
	)
	return patterns, nil
}

// ApplyIgnorePatterns applies the gitignore patterns to a list of files, removing matched.
func (d *Decomposer) applyIgnorePatterns(
	fileList []string, patterns []gitignore.Pattern,
) (filteredList []string) {
	logrus.Infof(
		"Applying %d ignore patterns to list of %d filenames",
		len(patterns), len(fileList),
	)
	// We will return a new file list
	filteredList = []string{}

	// Build the new gitignore matcher
	matcher := gitignore.NewMatcher(patterns)

	// Cycle all files, removing those matched:
	for _, file := range fileList {
		if matcher.Match(strings.Split(file, string(filepath.Separator)), false) {
			logrus.Debugf("File ignored by .gitignore: %s", file)
		} else {
			filteredList = append(filteredList, file)
		}
	}
	return filteredList
}

func (d *Decomposer) processFile(source fs.FS, path string) (*sbom.Node, error) {
	// Create the new file node
	node := sbom.NewNode()
	node.Type = sbom.Node_FILE
	node.FileName = path
	// node.FileTypes = []string{}
	node.PrimaryPurpose = append(node.PrimaryPurpose, sbom.Purpose_SOURCE)

	f, err := source.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	defer f.Close()

	hashes, err := d.Hasher.HashReaders([]io.Reader{f})
	if err != nil {
		return nil, fmt.Errorf("hashing %q: %w", path, err)
	}

	// We need to translate here
	for algo, val := range (*hashes)[0] {
		var at sbom.HashAlgorithm
		switch algo {
		case intoto.AlgorithmMD5:
			at = sbom.HashAlgorithm_MD5
		case intoto.AlgorithmSHA1:
			at = sbom.HashAlgorithm_SHA1
		case intoto.AlgorithmSHA224:
			at = sbom.HashAlgorithm_SHA224
		case intoto.AlgorithmSHA256, intoto.AlgorithmDirHash:
			at = sbom.HashAlgorithm_SHA256
		case intoto.AlgorithmSHA512:
			at = sbom.HashAlgorithm_SHA512
		case intoto.AlgorithmGitBlob, intoto.AlgorithmGitCommit, intoto.AlgorithmGitTag, intoto.AlgorithmGitTree:
			at = sbom.HashAlgorithm_SHA1
		default:
			continue
		}
		node.AddHash(at, val)
	}

	return node, nil
}

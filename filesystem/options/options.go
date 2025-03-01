// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"io/fs"
	"os"
	"slices"

	intoto "github.com/in-toto/attestation/go/v1"
)

type Function func(*Options) error

type Options struct {
	Filesystem     fs.FS                  // Filesystem to index
	NoGitignore    bool                   // Do not attempt to read the gitignore file
	IgnorePatterns []string               // Patterns to ignore when scanning file
	Algorithms     []intoto.HashAlgorithm // Algorithms to use when hashing
	Processors     []string               // Identifiers of file processors
}

var Default = Options{
	Algorithms: []intoto.HashAlgorithm{
		intoto.AlgorithmSHA1,
		intoto.AlgorithmSHA256,
		//intoto.AlgorithmSHA512,
	},
	Processors: []string{"hash"},
}

func WithNoGitIgnore() Function {
	return func(o *Options) error {
		o.NoGitignore = true
		return nil
	}
}

func WithIgnorePatterns(patterns []string) Function {
	return func(o *Options) error {
		o.IgnorePatterns = patterns
		return nil
	}
}

func WithAlgorithms(algos []intoto.HashAlgorithm) Function {
	return func(o *Options) error {
		// TODO check algos
		o.Algorithms = algos
		return nil
	}
}

func WithPath(path string) Function {
	return func(o *Options) error {
		o.Filesystem = os.DirFS(path)
		return nil
	}
}

func WithFilesystem(filesystem fs.FS) Function {
	return func(o *Options) error {
		o.Filesystem = filesystem
		return nil
	}
}

func WithFileProcessor(id string) Function {
	return func(o *Options) error {
		// if _, ok := FileProcessors[id]; !ok {
		// 	return fmt.Errorf("unknown file processor: %q", id)
		// }
		if !slices.Contains(o.Processors, id) {
			o.Processors = append(o.Processors, id)
		}
		return nil
	}
}

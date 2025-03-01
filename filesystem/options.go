// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"io/fs"
	"os"

	intoto "github.com/in-toto/attestation/go/v1"
)

type optFn func(*Options)

type Options struct {
	Filesystem     fs.FS                  // Filesystem to index
	NoGitignore    bool                   // Do not attempt to read the gitignore file
	IgnorePatterns []string               // Patterns to ignore when scanning file
	Algorithms     []intoto.HashAlgorithm // Algorithms to use when hashing
}

var defaultOptions = Options{
	Algorithms: []intoto.HashAlgorithm{
		intoto.AlgorithmSHA1,
		intoto.AlgorithmSHA256,
		intoto.AlgorithmSHA512,
	},
}

func WithNoGitIgnore() optFn {
	return func(o *Options) {
		o.NoGitignore = true
	}
}

func WithIgnorePatterns(patterns []string) optFn {
	return func(o *Options) {
		o.IgnorePatterns = patterns
	}
}

func WithAlgorithms(algos []intoto.HashAlgorithm) optFn {
	return func(o *Options) {
		o.Algorithms = algos
	}
}

func WithPath(path string) optFn {
	return func(o *Options) {
		o.Filesystem = os.DirFS(path)
	}
}

func WithFilesystem(filesystem fs.FS) optFn {
	return func(o *Options) {
		o.Filesystem = filesystem
	}
}

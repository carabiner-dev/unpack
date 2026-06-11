// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package system implements the unpacker that reads installed-package data
// from a "system" — the local machine, a container image, a VM image, etc.
package system

import (
	"fmt"
	"io/fs"
	"os"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// SubjectType is the DecomposableSubject type routed to the SystemPackages
// unpacker.
const SubjectType = "system"

// System is the DecomposableSubject consumed by the SystemPackages unpacker.
// A System is anything that has installed packages and exposes a filesystem
// the decomposers can inspect: the local machine, a container image, a VM
// image, etc.
type System interface {
	api.DecomposableSubject

	// FileSystem returns the system's root filesystem. Decomposers look up
	// package databases at paths relative to this root (e.g. "var/lib/rpm/...").
	FileSystem() (fs.FS, error)
}

// LocalSystem is a System subject describing the local machine. By default it
// exposes the OS root ("/"); set Root to point at a different directory, for
// example a mounted container or VM image root.
type LocalSystem struct {
	// Root is the path used as the filesystem root. Empty means "/".
	Root string
}

// DecomposableType identifies this subject as a system, routing it to the
// SystemPackages unpacker through the registry.
func (l *LocalSystem) DecomposableType() string { return SubjectType }

// FileSystem returns an fs.FS rooted at LocalSystem.Root (default "/"). Paths
// passed to the returned FS must be relative, so a decomposer reads the RPM
// database as "var/lib/rpm/Packages", not "/var/lib/rpm/Packages".
func (l *LocalSystem) FileSystem() (fs.FS, error) {
	root := l.Root
	if root == "" {
		root = "/"
	}
	return os.DirFS(root), nil
}

// Filesystem is a System subject wrapping an arbitrary fs.FS — a squashed
// container image, a mounted VM disk, a tar archive, etc. Unpackers that
// crack open such artifacts use it to route the inner filesystem to the
// SystemPackages unpacker through the registry.
type Filesystem struct {
	FS fs.FS
}

// DecomposableType identifies this subject as a system, routing it to the
// SystemPackages unpacker through the registry.
func (f *Filesystem) DecomposableType() string { return SubjectType }

// FileSystem returns the wrapped filesystem.
func (f *Filesystem) FileSystem() (fs.FS, error) {
	if f.FS == nil {
		return nil, fmt.Errorf("filesystem subject has no fs.FS")
	}
	return f.FS, nil
}

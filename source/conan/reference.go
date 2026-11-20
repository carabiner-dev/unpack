// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package conan

import (
	"fmt"
	"strings"
)

// Reference names a Conan package the way Conan writes it:
//
//	name/version[@user[/channel]][#recipe revision[%timestamp]]
//
// as in zlib/1.3.1#f52e03ae3d251dec704634230cd806a2%1708593606.497. A
// manifest may ask for a range in place of a version, zlib/[>=1.2 <2].
type Reference struct {
	Name    string
	Version string

	// Range is the version range a manifest asks for, without its
	// brackets, when it asks for one and not for a version.
	Range string

	User    string
	Channel string

	// Revision is the recipe revision: a hash of the recipe that builds
	// the package, and not of the package's sources or binaries.
	Revision string

	// Packages are the binaries a lockfile pins for the reference, when
	// it was made to lock them: package id to package revision, which is
	// empty for a binary not yet built.
	Packages map[string]string
}

// ParseReference reads a reference.
func ParseReference(raw string) (*Reference, error) {
	rest := strings.TrimSpace(raw)
	ref := &Reference{}

	// The revision and its timestamp close the reference.
	if before, revision, found := strings.Cut(rest, "#"); found {
		rest = before
		ref.Revision, _, _ = strings.Cut(revision, "%")
	}

	// A range may hold anything but a closing bracket, an @ included.
	name, version, found := strings.Cut(rest, "/")
	if !found || name == "" || version == "" {
		return nil, fmt.Errorf("conan reference %q is not name/version", raw)
	}
	ref.Name = name

	if strings.HasPrefix(version, "[") {
		end := strings.Index(version, "]")
		if end < 0 {
			return nil, fmt.Errorf("conan reference %q has a version range that is not closed", raw)
		}
		ref.Range = strings.TrimSpace(version[1:end])
		version = version[end+1:]
	}

	version, owner, _ := strings.Cut(version, "@")
	if ref.Range == "" {
		if version == "" {
			return nil, fmt.Errorf("conan reference %q has no version", raw)
		}
		ref.Version = version
	}
	// A user of "_" with a channel of "_" is how Conan 1 wrote none.
	if user, channel, _ := strings.Cut(owner, "/"); user != "_" {
		ref.User, ref.Channel = user, channel
	}
	return ref, nil
}

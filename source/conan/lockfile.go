// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package conan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// LockFile is the name Conan gives its lockfile and looks for by default.
const LockFile = "conan.lock"

// ErrLegacyLockfile is returned for a lockfile in the format of Conan 1,
// which is another document altogether: a graph of nodes, where Conan 2
// writes lists of references.
var ErrLegacyLockfile = errors.New("the lockfile is in the Conan 1 format, which is not read")

// Lock is a Conan 2 lockfile: the packages a dependency graph resolved
// to, as flat lists, each sorted newest first. It says which packages and
// not which of them requires which.
//
// The lists go by the context a package is used in: what is built into
// the project or its tests is in Requires, what runs on the build
// machine in BuildRequires. A lockfile also holds the overrides of the
// graph, which name no package of their own and are not read.
type Lock struct {
	Version string

	// Requires are the packages the project is built from and links.
	Requires []*Reference

	// BuildRequires are the packages its build uses: tools, and what its
	// tests need.
	BuildRequires []*Reference

	// PythonRequires are the packages its recipe is written with.
	PythonRequires []*Reference

	// ConfigRequires are the packages Conan's own configuration is
	// installed from.
	ConfigRequires []*Reference
}

type rawLock struct {
	Version        string            `json:"version"`
	GraphLock      json.RawMessage   `json:"graph_lock"`
	Requires       []json.RawMessage `json:"requires"`
	BuildRequires  []json.RawMessage `json:"build_requires"`
	PythonRequires []json.RawMessage `json:"python_requires"`
	ConfigRequires []json.RawMessage `json:"config_requires"`
}

// parseEntry reads one entry of a lockfile list: a reference, or when the
// lockfile also locks binaries a pair of the reference and its package
// ids with their revisions.
func parseEntry(raw json.RawMessage) (*Reference, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return ParseReference(text)
	}

	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil || len(pair) == 0 {
		return nil, fmt.Errorf("lockfile entry %s is neither a reference nor a reference with its packages", raw)
	}
	if err := json.Unmarshal(pair[0], &text); err != nil {
		return nil, fmt.Errorf("lockfile entry %s does not open with a reference", raw)
	}
	ref, err := ParseReference(text)
	if err != nil {
		return nil, err
	}
	if len(pair) > 1 {
		packages := map[string]*string{}
		if err := json.Unmarshal(pair[1], &packages); err != nil {
			return nil, fmt.Errorf("lockfile entry %s: reading its packages: %w", raw, err)
		}
		ref.Packages = map[string]string{}
		for id, revision := range packages {
			ref.Packages[id] = ""
			if revision != nil {
				ref.Packages[id] = *revision
			}
		}
	}
	return ref, nil
}

// ReadLock reads a lockfile.
func ReadLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParseLock(data)
}

// ParseLock reads the contents of a lockfile.
func ParseLock(data []byte) (*Lock, error) {
	raw := &rawLock{}
	if err := json.Unmarshal(data, raw); err != nil {
		return nil, fmt.Errorf("parsing lockfile: %w", err)
	}
	if len(raw.GraphLock) > 0 {
		return nil, ErrLegacyLockfile
	}

	lock := &Lock{Version: raw.Version}
	for _, list := range []struct {
		from []json.RawMessage
		to   *[]*Reference
	}{
		{raw.Requires, &lock.Requires},
		{raw.BuildRequires, &lock.BuildRequires},
		{raw.PythonRequires, &lock.PythonRequires},
		{raw.ConfigRequires, &lock.ConfigRequires},
	} {
		for _, entry := range list.from {
			ref, err := parseEntry(entry)
			if err != nil {
				return nil, fmt.Errorf("parsing lockfile: %w", err)
			}
			*list.to = append(*list.to, ref)
		}
	}
	return lock, nil
}

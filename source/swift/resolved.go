// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// ResolvedFile is the name of the lockfile of the Swift Package Manager.
const ResolvedFile = "Package.resolved"

// Kinds of a pin: where the package is fetched from.
const (
	KindRemote   = "remoteSourceControl"
	KindLocal    = "localSourceControl"
	KindRegistry = "registry"
)

// Resolved is a Package.resolved: the packages a project's dependencies
// resolved to, as a flat list. It says which packages and not which of
// them requires which.
type Resolved struct {
	// Version is the schema of the file. SwiftPM has written three: 1
	// nests the pins and names them by URL, 2 names them by identity
	// and kind, and 3 is 2 with a hash of what the file was resolved
	// from.
	Version int
	Pins    []*Pin
}

// Pin is one resolved package.
type Pin struct {
	// Identity is what SwiftPM knows the package by: for a repository
	// the last element of its URL, in lower case and without ".git";
	// for a package of a registry its scope and name, "scope.name".
	Identity string
	Kind     string

	// Location is the repository's URL, or for a local repository its
	// path. A registry pin has none.
	Location string

	// The state: the version when the package is pinned to one, the
	// branch when it follows one, and the commit either way. A registry
	// pin has a version and no commit.
	Version  string
	Branch   string
	Revision string
}

// ErrMalformed is returned for a Package.resolved that cannot be read.
var ErrMalformed = errors.New("malformed Package.resolved")

type rawState struct {
	Version  *string `json:"version"`
	Branch   *string `json:"branch"`
	Revision *string `json:"revision"`
}

type rawPin struct {
	// Schemas 2 and 3.
	Identity string `json:"identity"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
	// Schema 1.
	Package       string `json:"package"`
	RepositoryURL string `json:"repositoryURL"`

	State rawState `json:"state"`
}

type rawResolved struct {
	Version int      `json:"version"`
	Pins    []rawPin `json:"pins"`
	Object  struct {
		Pins []rawPin `json:"pins"`
	} `json:"object"`
}

// ReadResolved reads a Package.resolved.
func ReadResolved(file string) (*Resolved, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ResolvedFile, err)
	}
	return ParseResolved(data)
}

// ParseResolved reads the contents of a Package.resolved, in any of its
// schemas. A schema newer than the ones known is read as the newest
// known: each so far has kept the pins of the one before.
func ParseResolved(data []byte) (*Resolved, error) {
	raw := &rawResolved{}
	if err := json.Unmarshal(data, raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if raw.Version < 1 {
		return nil, fmt.Errorf("%w: it states no schema version", ErrMalformed)
	}

	pins := raw.Pins
	if raw.Version == 1 {
		pins = raw.Object.Pins
	}
	resolved := &Resolved{Version: raw.Version}
	for i := range pins {
		pin, err := pins[i].pin()
		if err != nil {
			return nil, err
		}
		resolved.Pins = append(resolved.Pins, pin)
	}
	// SwiftPM writes the pins sorted by identity; a file edited by hand
	// may not be.
	sort.SliceStable(resolved.Pins, func(i, j int) bool { return resolved.Pins[i].Identity < resolved.Pins[j].Identity })
	return resolved, nil
}

func value(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// pin reads one pin of either shape.
func (r *rawPin) pin() (*Pin, error) {
	pin := &Pin{
		Identity: r.Identity, Kind: r.Kind, Location: r.Location,
		Version: value(r.State.Version), Branch: value(r.State.Branch), Revision: value(r.State.Revision),
	}
	// The first schema has no identity or kind: a pin is a repository,
	// known by its URL.
	if pin.Identity == "" && r.RepositoryURL != "" {
		pin.Location = r.RepositoryURL
		pin.Identity = IdentityOf(r.RepositoryURL)
		pin.Kind = KindRemote
		if strings.HasPrefix(r.RepositoryURL, "/") {
			pin.Kind = KindLocal
		}
	}
	if pin.Identity == "" {
		return nil, fmt.Errorf("%w: a pin has no identity", ErrMalformed)
	}
	if pin.Version == "" && pin.Revision == "" {
		return nil, fmt.Errorf("%w: pin %s has neither a version nor a revision", ErrMalformed, pin.Identity)
	}
	return pin, nil
}

// IdentityOf returns the identity SwiftPM gives the package of a
// repository: the last element of its location, without ".git", in lower
// case.
func IdentityOf(location string) string {
	trimmed := strings.TrimRight(location, "/")
	// An scp-style location, git@host:org/repo.git, has its path after
	// the colon.
	if i := strings.LastIndexAny(trimmed, "/:"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	return strings.ToLower(strings.TrimSuffix(path.Base(trimmed), ".git"))
}

// ComponentVersion returns the version SwiftPM's own SBOMs give the
// package: the version it is pinned to, and for one pinned to a branch
// or a bare commit, the commit.
func (p *Pin) ComponentVersion() string {
	if p.Version != "" {
		return p.Version
	}
	return p.Revision
}

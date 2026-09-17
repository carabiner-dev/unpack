// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gobinary implements the artifact decomposer for Go executables.
// Every binary the Go toolchain links since module support carries its
// build information: the main module, the exact set of modules linked into
// it with their versions and checksums, the Go release and the build
// settings. The decomposer reads that record with debug/buildinfo and
// renders it through the Go source decomposer's graph builder, so a binary
// and the codebase it came from produce the same shape of graph.
package gobinary

import (
	"debug/buildinfo"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime/debug"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/source/golang"
)

var (
	_ api.Decomposer      = (*Decomposer)(nil)
	_ api.SubjectDefaults = (*Decomposer)(nil)
)

// Name is the name the decomposer is registered under in the artifact
// unpacker, and the key options refer to it by.
const Name = "gobinary"

// develVersion is the version Go stamps on a main module built outside a
// tagged release when VCS data is unavailable.
const develVersion = "(devel)"

// Property names recorded on the root node from the binary's build settings.
const (
	PropertyGOOS    = "goos"
	PropertyGOARCH  = "goarch"
	PropertyPackage = "go:package"
)

// Decomposer reads dependency data out of Go executables.
type Decomposer struct {
	golang *golang.Decomposer
}

// New returns a Go binary decomposer.
func New() *Decomposer {
	return &Decomposer{golang: golang.New()}
}

// Name returns the decomposer's registration name.
func (d *Decomposer) Name() string { return Name }

// DefaultSubjects lists the parents the decomposer runs under by default: a
// container image or a system root, where executables are the payload. A
// codebase is not among them, so `unpack extract` does not probe binaries
// it finds lying around a source tree unless asked to.
func (d *Decomposer) DefaultSubjects() []string {
	return []string{"image", "system"}
}

// DefaultOptions returns the options of the Go source decomposer, which does
// the graph resolution and license enrichment. Set them as this decomposer's
// driver options to control the module proxy, concurrency and cache use.
func (d *Decomposer) DefaultOptions() any {
	return d.golang.DefaultOptions()
}

// Requirements returns nothing: the decomposer is pure Go.
func (d *Decomposer) Requirements(*api.DecomposerOptions) []api.Requirement {
	return nil
}

// Extract reads the executable at opts.WorkDir. It is the plain api.Decomposer
// entry point; the artifact unpacker uses ExtractArtifact.
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, fmt.Errorf("gobinary decomposer needs a WorkDir naming the executable")
	}
	f, err := os.Open(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("opening executable: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	return d.ExtractArtifact(f, opts.WorkDir, opts)
}

// Matches reports whether the file looks like an executable in one of the
// formats debug/buildinfo reads: ELF, PE or Mach-O. The check is on the
// magic number alone; whether the executable is a Go program is settled by
// ExtractArtifact.
func (d *Decomposer) Matches(_ fs.FileInfo, header []byte) bool {
	if len(header) < 4 {
		return false
	}
	switch {
	case string(header[:4]) == "\x7fELF":
		return true
	case header[0] == 'M' && header[1] == 'Z':
		return true
	}
	switch string(header[:4]) {
	case "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", // Mach-O 32/64, big endian
		"\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe": // Mach-O 32/64, little endian
		return true
	}
	return false
}

// ExtractArtifact reads the build information embedded in the executable and
// returns the program's module graph: the main module as the root, with the
// modules linked into the binary as its dependencies. Returns (nil, nil)
// when the file carries no Go build information, which is what any
// executable not built by the Go toolchain looks like.
func (d *Decomposer) ExtractArtifact(ra io.ReaderAt, _ string, opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil {
		opts = &api.DecomposerOptions{}
	}

	// buildinfo.Read fails on files that are not executables in a format it
	// knows, on executables that are not Go programs, and on Go programs
	// built without module support. It does not distinguish those from a
	// read that went wrong, so every failure disowns the file.
	bi, err := buildinfo.Read(ra)
	if err != nil {
		return nil, nil //nolint:nilerr // not a Go binary, see above
	}

	set := ModuleSetFromBuildInfo(bi)
	if set.Main.Path == "" {
		// No main module and no main package: built without modules.
		return nil, nil
	}

	inner := &api.DecomposerOptions{
		Version:    opts.Version,
		CommitHash: opts.CommitHash,
		Networking: opts.Networking,
		Platform:   opts.Platform,
	}
	if inner.Version == "" && set.Main.Version != "" && set.Main.Version != develVersion {
		inner.Version = set.Main.Version
	}
	settings := buildSettings(bi)
	if inner.CommitHash == "" {
		inner.CommitHash = settings["vcs.revision"]
	}
	if inner.Platform == "" && settings["GOOS"] != "" {
		inner.Platform = settings["GOOS"]
		if settings["GOARCH"] != "" {
			inner.Platform += "/" + settings["GOARCH"]
		}
	}
	if gOpts := opts.GetDriverOptions(d); gOpts != nil {
		inner.SetDriverOptions(d.golang, gOpts)
	}

	nl, err := d.golang.BuildNodeList(set, inner)
	if err != nil {
		return nil, fmt.Errorf("building module graph: %w", err)
	}

	// The root is a program, not a library, and it carries the build
	// settings that identify what was built and for where.
	for _, id := range nl.GetRootElements() {
		root := nl.GetNodeByID(id)
		if root == nil {
			continue
		}
		root.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
		for _, p := range []struct{ name, value string }{
			{PropertyPackage, bi.Path},
			{PropertyGOOS, settings["GOOS"]},
			{PropertyGOARCH, settings["GOARCH"]},
		} {
			if p.value != "" {
				root.Properties = append(root.Properties, &sbom.Property{Name: p.name, Data: p.value})
			}
		}
	}
	return nl, nil
}

// ModuleSetFromBuildInfo reduces a binary's build information to the module
// set the Go graph builder renders. The main module is the root; when the
// binary was built outside a module, the main package path stands in for
// it. Every linked module is both required by the root and a member of the
// set: build information does not say which modules the main module
// requires directly, so the honest graph is flat from the root, with edges
// among the linked modules resolved by the builder when networking allows.
//
// Replaced modules enter the set as what was actually linked, the
// replacement, with the original recorded in Replaces so requirements
// naming the original resolve to it. A replacement by a local directory
// has no version or checksum worth recording, so the original module is
// kept instead, as the go.mod reader does.
func ModuleSetFromBuildInfo(bi *debug.BuildInfo) *golang.ModuleSet {
	set := &golang.ModuleSet{
		Main:      golang.Module{Path: bi.Main.Path, Version: bi.Main.Version},
		GoVersion: goRelease(bi.GoVersion),
		Replaces:  map[string]golang.Replacement{},
	}
	if set.Main.Path == "" {
		set.Main.Path = bi.Path
	}

	seen := make(map[string]struct{}, len(bi.Deps))
	for _, dep := range bi.Deps {
		if dep == nil {
			continue
		}
		linked := dep
		if dep.Replace != nil && dep.Replace.Path != "" && !isLocalPath(dep.Replace.Path) {
			linked = dep.Replace
			repl := golang.Replacement{Path: dep.Replace.Path, Version: dep.Replace.Version}
			set.Replaces[dep.Path] = repl
			set.Replaces[dep.Path+"@"+dep.Version] = repl
		}
		m := golang.Module{Path: linked.Path, Version: linked.Version}
		if linked.Sum != "" {
			m.Sums = []string{linked.Sum}
		}
		if _, dup := seen[m.Key()]; dup {
			continue
		}
		seen[m.Key()] = struct{}{}
		set.Requires = append(set.Requires, m)
		set.Modules = append(set.Modules, m)
	}
	return set
}

// goRelease extracts the Go release from a build info GoVersion string:
// "go1.24.0" gives "1.24.0" and a development toolchain such as
// "devel go1.25-0123abcd Mon Jan 1" gives "1.25-0123abcd". Anything without
// a go-prefixed field yields an empty string and no stdlib node.
func goRelease(goVersion string) string {
	for _, field := range strings.Fields(goVersion) {
		if rest, ok := strings.CutPrefix(field, "go"); ok && rest != "" {
			return rest
		}
	}
	return ""
}

// isLocalPath reports whether a replacement path names a directory rather
// than a module.
func isLocalPath(path string) bool {
	return strings.HasPrefix(path, "./") ||
		strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, "/") ||
		path == "." || path == ".."
}

// buildSettings indexes the build info settings by key.
func buildSettings(bi *debug.BuildInfo) map[string]string {
	settings := make(map[string]string, len(bi.Settings))
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	return settings
}

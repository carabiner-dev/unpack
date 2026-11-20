// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmake

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// This file reads what a CMake project says it depends on, without
// running CMake.
//
// A CMake project has no lockfile and no manifest. It is a program: it
// asks the machine it is configured on for the packages it wants
// (find_package, pkg_check_modules), or fetches them (FetchContent,
// ExternalProject), and which of those commands run depends on options
// and on what is installed. Reading the files gives the commands the
// project holds, which is what it may depend on, and not what one build
// of it found.
//
// What is read is therefore labelled with how sure it is: a dependency
// the default configuration requires, one the build goes on without, one
// behind a condition that cannot be told from the files, and one behind
// an option that is off unless asked for.

const listsFile = "CMakeLists.txt"

// Commands and keywords read in more than one place.
const (
	commandPkgCheck  = "pkg_check_modules"
	commandPkgSearch = "pkg_search_module"
	keywordRequired  = "REQUIRED"
)

// Status says how sure it is that a build of the project has a
// dependency. The values are ordered: of the places a dependency is asked
// for, the surest one counts.
type Status int

const (
	// StatusDisabled is a dependency asked for where the default
	// configuration does not go: behind an option that is off.
	StatusDisabled Status = iota

	// StatusConditional is one behind a condition the files do not
	// settle: the result of another lookup, the platform, a variable
	// given on the command line.
	StatusConditional

	// StatusOptional is one the default configuration asks for and goes
	// on without: a find_package with no REQUIRED.
	StatusOptional

	// StatusRequired is one the default configuration does not configure
	// without.
	StatusRequired
)

func (s Status) String() string {
	switch s {
	case StatusRequired:
		return "required"
	case StatusOptional:
		return "optional"
	case StatusConditional:
		return "conditional"
	case StatusDisabled:
		return "disabled"
	}
	return "disabled"
}

// Dependency is one package a project asks for, with every place it asks
// for it folded together.
type Dependency struct {
	Name   string
	Status Status

	// Version is the version the project pins: a fetched tag or commit,
	// or a find_package with EXACT. A lookup on the machine pins none.
	Version string

	// Constraint is the range the project accepts when it pins nothing,
	// as in ">=2.3.1".
	Constraint string

	// Commands are the commands that ask for it, sorted.
	Commands []string

	// PkgConfig are the pkg-config modules it is looked up as.
	PkgConfig []string

	// Where a fetched dependency comes from.
	Repository string
	URL        string
	HashAlgo   string
	Hash       string

	// Declared lists where it is asked for, as file:line, sorted.
	Declared []string
}

// Project is what the files of a CMake project say of it.
type Project struct {
	Name         string
	Version      string
	Dependencies []*Dependency

	// Skipped are the files that could not be read as CMake.
	Skipped []string
}

// Names find_package takes that are no package. Both are modules CMake
// ships: FindPkgConfig finds the pkg-config tool the build runs, and
// FindThreads the thread library of the system.
var notPackages = map[string]bool{"pkgconfig": true, "threads": true}

// file is one parsed CMake file of the project.
type file struct {
	path     string // relative to the project, slash separated
	commands []Command
}

// reader accumulates what the files say.
type reader struct {
	variables map[string]string
	ambiguous map[string]bool
	options   map[string]bool
	deps      map[string]*Dependency
	modules   map[string]*findModule

	// subdirs is whether the default configuration enters a directory,
	// as the add_subdirectory commands naming it say.
	subdirs map[string]conditionState
}

// findModule is what a Find<Name>.cmake of the project says of the
// package it finds: the pkg-config modules it looks it up as.
type findModule struct {
	pkgConfig  []string
	constraint string

	// wraps are the packages the module finds through find_package: a
	// module of the project's own may only dress up the lookup of a
	// package that goes by another name, as a FindYAMLCPP.cmake that
	// looks for yaml-cpp. They are what the project depends on.
	wraps []*Dependency
}

// ReadProject reads the CMake project at a directory.
func ReadProject(dir string) (*Project, error) {
	files, skipped, err := loadFiles(dir)
	if err != nil {
		return nil, err
	}

	r := &reader{
		variables: map[string]string{},
		ambiguous: map[string]bool{},
		options:   map[string]bool{},
		deps:      map[string]*Dependency{},
		modules:   map[string]*findModule{},
		subdirs:   map[string]conditionState{},
	}
	project := &Project{Skipped: skipped}

	// First what the files define, which a command may use from another
	// file; then the commands.
	for _, f := range files {
		r.collectDefinitions(f, project)
	}
	for _, f := range files {
		if name, ok := findModuleName(f.path); ok {
			r.readFindModule(name, f)
		}
	}
	for _, f := range files {
		if _, ok := findModuleName(f.path); ok {
			continue
		}
		r.readCommands(f)
	}

	// A package asked for through a module that wraps others is asked for
	// as those: with the same certainty, from the same places.
	for key, module := range r.modules {
		wrapper := r.deps[key]
		if wrapper == nil || len(module.wraps) == 0 {
			continue
		}
		delete(r.deps, key)
		for _, wrapped := range module.wraps {
			found := *wrapped
			found.Status = wrapper.Status
			found.Commands, found.Declared = wrapper.Commands, wrapper.Declared
			found.PkgConfig = module.pkgConfig
			if found.Constraint == "" && found.Version == "" {
				found.Constraint = module.constraint
			}
			r.merge(&found)
		}
	}

	for key, dep := range r.deps {
		if module := r.modules[key]; module != nil {
			dep.PkgConfig = mergeSorted(dep.PkgConfig, module.pkgConfig)
			if dep.Constraint == "" {
				dep.Constraint = module.constraint
			}
		}
		sort.Strings(dep.Commands)
		sort.Strings(dep.Declared)
		project.Dependencies = append(project.Dependencies, dep)
	}
	sort.Slice(project.Dependencies, func(i, j int) bool {
		return strings.ToLower(project.Dependencies[i].Name) < strings.ToLower(project.Dependencies[j].Name)
	})

	if project.Name == "" {
		if abs, err := filepath.Abs(dir); err == nil {
			project.Name = filepath.Base(abs)
		}
	}
	return project, nil
}

// loadFiles parses the CMake files of a project: every CMakeLists.txt and
// *.cmake under its directory, the root's first.
//
// A directory below the root that declares a project of its own is
// another project, vendored or an example, and is left out with what is
// under it: what it asks for is not this project's to state. So is a
// build tree, which holds the files CMake generated.
func loadFiles(dir string) (files []*file, skipped []string, err error) {
	if _, err := os.Stat(filepath.Join(dir, listsFile)); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", listsFile, err)
	}

	parsed := map[string]*file{}
	nested := []string{}
	fsys := os.DirFS(dir)
	walkErr := fs.WalkDir(fsys, ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory is passed over
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "_deps" {
				return fs.SkipDir
			}
			if _, err := fs.Stat(fsys, path.Join(rel, "CMakeCache.txt")); err == nil {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != listsFile && !strings.HasSuffix(d.Name(), ".cmake") {
			return nil
		}

		// A file that cannot be read, or holds a mistake, is named to
		// the caller; what was read before the mistake still counts.
		data, readErr := fs.ReadFile(fsys, rel)
		commands, parseErr := Parse(string(data))
		if readErr != nil || parseErr != nil {
			skipped = append(skipped, rel)
		}
		parsed[rel] = &file{path: rel, commands: commands}
		if d.Name() == listsFile && rel != listsFile && declaresProject(commands) {
			nested = append(nested, path.Dir(rel)+"/")
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("walking the project: %w", walkErr)
	}

	paths := make([]string, 0, len(parsed))
	for rel := range parsed {
		if !slices.ContainsFunc(nested, func(prefix string) bool { return strings.HasPrefix(rel, prefix) }) {
			paths = append(paths, rel)
		}
	}
	// Outer directories first: whether a directory is entered is said by
	// the one above it.
	sort.Slice(paths, func(i, j int) bool {
		if di, dj := strings.Count(paths[i], "/"), strings.Count(paths[j], "/"); di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})
	for _, rel := range paths {
		files = append(files, parsed[rel])
	}
	sort.Strings(skipped)
	return files, skipped, nil
}

func declaresProject(commands []Command) bool {
	return slices.ContainsFunc(commands, func(c Command) bool { return c.Name == "project" })
}

// findModuleName returns the package a file is the find module of:
// FindROHC.cmake finds ROHC.
func findModuleName(rel string) (string, bool) {
	base := path.Base(rel)
	if !strings.HasPrefix(base, "Find") || !strings.HasSuffix(base, ".cmake") {
		return "", false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(base, "Find"), ".cmake")
	return name, name != ""
}

// collectDefinitions records the variables and options a file defines,
// and the project the root declares.
//
// Only what is plain is kept: a variable set to one literal value. One
// set to different values in different places has no value that can be
// read off the files.
func (r *reader) collectDefinitions(f *file, project *Project) {
	for i := range f.commands {
		command := &f.commands[i]
		args := command.Values()
		switch command.Name {
		case "project":
			if f.path != listsFile || len(args) == 0 || project.Name != "" {
				continue
			}
			project.Name = args[0]
			for j := 1; j+1 < len(args); j++ {
				if args[j] == "VERSION" && !command.Args[j].Quoted {
					project.Version = args[j+1]
				}
			}
			r.define("PROJECT_NAME", project.Name)
			r.define("CMAKE_PROJECT_NAME", project.Name)
			if project.Version != "" {
				r.define("PROJECT_VERSION", project.Version)
				r.define("CMAKE_PROJECT_VERSION", project.Version)
			}
		case "set":
			if len(args) < 2 {
				continue
			}
			// set(NAME value) or set(NAME value CACHE TYPE doc ...).
			if len(args) == 2 || args[2] == "CACHE" || args[2] == "PARENT_SCOPE" {
				r.define(args[0], args[1])
			} else {
				r.ambiguous[args[0]] = true
			}
		case "option":
			if len(args) == 0 {
				continue
			}
			r.options[args[0]] = len(args) >= 3 && truth(args[2]) == stateOn
		}
	}
}

func (r *reader) define(name, value string) {
	if previous, ok := r.variables[name]; ok && previous != value {
		r.ambiguous[name] = true
	}
	r.variables[name] = value
}

var reference = regexp.MustCompile(`\$\{([A-Za-z0-9_.+\-]+)\}`)

// expand replaces the variable references of a value with what the files
// define, and says whether every one of them was resolved.
func (r *reader) expand(value string) (string, bool) {
	for range 8 {
		if !strings.Contains(value, "${") {
			return value, true
		}
		resolved := true
		value = reference.ReplaceAllStringFunc(value, func(ref string) string {
			name := reference.FindStringSubmatch(ref)[1]
			if replacement, ok := r.variables[name]; ok && !r.ambiguous[name] {
				return replacement
			}
			resolved = false
			return ref
		})
		if !resolved {
			return value, false
		}
	}
	return value, !strings.Contains(value, "${")
}

// readFindModule reads what a find module looks its package up as.
func (r *reader) readFindModule(name string, f *file) {
	module := &findModule{}
	for i := range f.commands {
		command := &f.commands[i]
		if command.Name == "find_package" {
			wrapped := r.packageOf(command)
			if wrapped != nil && !notPackages[strings.ToLower(wrapped.Name)] && !strings.EqualFold(wrapped.Name, name) {
				module.wraps = append(module.wraps, wrapped)
			}
			continue
		}
		if command.Name != commandPkgCheck && command.Name != commandPkgSearch {
			continue
		}
		for _, spec := range r.pkgConfigSpecs(command) {
			module.pkgConfig = mergeSorted(module.pkgConfig, []string{spec.name})
			if module.constraint == "" {
				module.constraint = spec.constraint
			}
		}
	}
	if len(module.pkgConfig) > 0 || len(module.wraps) > 0 {
		r.modules[strings.ToLower(name)] = module
	}
}

// readCommands reads the commands of a file that ask for a dependency,
// each with how sure it is to run.
func (r *reader) readCommands(f *file) {
	conditions := &conditionStack{}
	dir := path.Dir(f.path)
	base := r.entered(dir)

	for i := range f.commands {
		command := &f.commands[i]
		if conditions.step(command, r) {
			continue
		}

		where := fmt.Sprintf("%s:%d", f.path, command.Line)
		state := both(base, conditions.state())
		switch command.Name {
		case "add_subdirectory":
			if len(command.Args) == 0 {
				continue
			}
			if sub, ok := r.expand(command.Args[0].Value); ok && !path.IsAbs(sub) {
				sub = path.Join(dir, sub)
				// Named in several places, it is entered if any of
				// them runs.
				if previous, seen := r.subdirs[sub]; !seen || surer(state, previous) {
					r.subdirs[sub] = state
				}
			}
		case "find_package":
			r.findPackage(command, state, where)
		case commandPkgCheck, commandPkgSearch:
			r.pkgConfig(command, state, where)
		case "fetchcontent_declare", "externalproject_add":
			r.fetched(command, state, where)
		}
	}
}

// entered says whether the default configuration reads the files of a
// directory: when the add_subdirectory naming it runs, and the one naming
// the directory above it. A directory no command names with a plain path
// is taken as entered: it may be named through a variable.
func (r *reader) entered(dir string) conditionState {
	state := stateOn
	for dir != "." && dir != "/" && dir != "" {
		if declared, ok := r.subdirs[dir]; ok {
			state = both(state, declared)
		}
		dir = path.Dir(dir)
	}
	return state
}

// both is the state of what needs two things to run.
func both(a, b conditionState) conditionState {
	switch {
	case a == stateOff || b == stateOff:
		return stateOff
	case a == stateUnknown || b == stateUnknown:
		return stateUnknown
	}
	return stateOn
}

// surer says whether a state is likelier to run than another.
func surer(a, b conditionState) bool {
	rank := map[conditionState]int{stateOff: 0, stateUnknown: 1, stateOn: 2}
	return rank[a] > rank[b]
}

// status turns whether a command asks for its package for good, and
// whether it runs, into how sure the dependency is.
func status(required bool, state conditionState) Status {
	switch {
	case state == stateOff:
		return StatusDisabled
	case state == stateUnknown:
		return StatusConditional
	case required:
		return StatusRequired
	default:
		return StatusOptional
	}
}

// add folds one request for a dependency into what is known of it.
func (r *reader) add(found *Dependency, command, where string) {
	if notPackages[strings.ToLower(found.Name)] {
		return
	}
	found.Commands = []string{command}
	found.Declared = []string{where}
	r.merge(found)
}

// merge folds what one request says of a dependency into what the others
// said.
func (r *reader) merge(found *Dependency) {
	key := strings.ToLower(found.Name)
	dep, known := r.deps[key]
	if !known {
		r.deps[key] = found
		return
	}

	// The surest request counts.
	dep.Status = max(dep.Status, found.Status)
	dep.Commands = mergeSorted(dep.Commands, found.Commands)
	dep.Declared = mergeSorted(dep.Declared, found.Declared)
	dep.PkgConfig = mergeSorted(dep.PkgConfig, found.PkgConfig)
	if dep.Version == "" {
		dep.Version = found.Version
	}
	if dep.Constraint == "" {
		dep.Constraint = found.Constraint
	}
	if dep.Repository == "" {
		dep.Repository = found.Repository
	}
	if dep.URL == "" {
		dep.URL, dep.HashAlgo, dep.Hash = found.URL, found.HashAlgo, found.Hash
	}
}

var versionArgument = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*(\.\.\.<?[0-9]+(\.[0-9]+)*)?$`)

// findPackage reads find_package(<Name> [version] [EXACT] [REQUIRED] ...).
func (r *reader) findPackage(command *Command, state conditionState, where string) {
	dep := r.packageOf(command)
	if dep == nil {
		return
	}
	required := slices.ContainsFunc(command.Args[1:], func(a Argument) bool { return !a.Quoted && a.Value == keywordRequired })
	dep.Status = status(required, state)
	r.add(dep, "find_package", where)
}

// packageOf reads the package a find_package command names, and the
// version it asks for.
func (r *reader) packageOf(command *Command) *Dependency {
	if len(command.Args) == 0 {
		return nil
	}
	name, ok := r.expand(command.Args[0].Value)
	if !ok || name == "" {
		return nil
	}

	dep := &Dependency{Name: name}
	exact, version := false, ""
	for i, arg := range command.Args[1:] {
		value, resolved := r.expand(arg.Value)
		switch {
		case arg.Quoted:
		case value == "EXACT":
			exact = true
		case i == 0 && resolved && versionArgument.MatchString(value):
			version = value
		}
	}
	switch {
	case version == "":
	case exact:
		dep.Version = version
	case strings.Contains(version, "..."):
		dep.Constraint = version
	default:
		dep.Constraint = ">=" + version
	}
	return dep
}

// pkgConfigSpec is one module of a pkg-config lookup.
type pkgConfigSpec struct {
	name       string
	constraint string
}

var pkgConfigKeywords = map[string]bool{
	keywordRequired: true, "QUIET": true, "IMPORTED_TARGET": true, "GLOBAL": true,
	"NO_CMAKE_PATH": true, "NO_CMAKE_ENVIRONMENT_PATH": true,
}

var pkgConfigModule = regexp.MustCompile(`^([A-Za-z0-9_.+\-]+)\s*(>=|<=|=|>|<)?\s*([A-Za-z0-9_.+\-]*)$`)

// pkgConfigSpecs reads the modules of pkg_check_modules(<prefix> ...),
// each a name or a name with a version, as in "rohc>=2.3.1".
func (r *reader) pkgConfigSpecs(command *Command) []pkgConfigSpec {
	specs := []pkgConfigSpec{}
	if len(command.Args) < 2 {
		return specs
	}
	for _, arg := range command.Args[1:] {
		if !arg.Quoted && pkgConfigKeywords[arg.Value] {
			continue
		}
		// The version may be in a variable the files do not settle; the
		// name still stands.
		value, _ := r.expand(arg.Value)
		match := pkgConfigModule.FindStringSubmatch(strings.TrimSpace(value))
		if match == nil {
			if name, _, found := strings.Cut(value, ">="); found && pkgConfigModule.MatchString(strings.TrimSpace(name)) {
				specs = append(specs, pkgConfigSpec{name: strings.TrimSpace(name)})
			}
			continue
		}
		spec := pkgConfigSpec{name: match[1]}
		if match[2] != "" && match[3] != "" {
			spec.constraint = match[2] + match[3]
		}
		specs = append(specs, spec)
	}
	return specs
}

// pkgConfig reads a pkg-config lookup. pkg_search_module takes the first
// of its modules that is installed, so only the first is named.
func (r *reader) pkgConfig(command *Command, state conditionState, where string) {
	required := slices.ContainsFunc(command.Args, func(a Argument) bool { return !a.Quoted && a.Value == keywordRequired })
	specs := r.pkgConfigSpecs(command)
	if command.Name == commandPkgSearch && len(specs) > 1 {
		specs = specs[:1]
	}
	for _, spec := range specs {
		dep := &Dependency{
			Name:      spec.name,
			Status:    status(required, state),
			PkgConfig: []string{spec.name},
		}
		if version, exact := strings.CutPrefix(spec.constraint, "="); exact {
			dep.Version = version
		} else {
			dep.Constraint = spec.constraint
		}
		r.add(dep, command.Name, where)
	}
}

// fetched reads FetchContent_Declare(<name> ...) and
// ExternalProject_Add(<name> ...), which say where a dependency is
// downloaded from and at which revision. What is fetched is built with
// the project, so it is required wherever the command runs.
func (r *reader) fetched(command *Command, state conditionState, where string) {
	if len(command.Args) == 0 {
		return
	}
	name, ok := r.expand(command.Args[0].Value)
	if !ok || name == "" {
		return
	}

	dep := &Dependency{Name: name, Status: status(true, state)}
	for i := 1; i+1 < len(command.Args); i++ {
		value, resolved := r.expand(command.Args[i+1].Value)
		if !resolved {
			continue
		}
		switch command.Args[i].Value {
		case "GIT_REPOSITORY":
			dep.Repository = value
		case "GIT_TAG":
			dep.Version = value
		case "URL":
			dep.URL = value
		case "URL_HASH":
			if algo, hash, found := strings.Cut(value, "="); found {
				dep.HashAlgo, dep.Hash = strings.ToUpper(algo), strings.ToLower(hash)
			}
		case "URL_MD5":
			dep.HashAlgo, dep.Hash = "MD5", strings.ToLower(value)
		}
	}

	display := "FetchContent_Declare"
	if command.Name == "externalproject_add" {
		display = "ExternalProject_Add"
	}
	r.add(dep, display, where)
}

// mergeSorted returns the two lists as one, sorted, each value once.
func mergeSorted(a, b []string) []string {
	merged := slices.Clone(a)
	for _, value := range b {
		if value != "" && !slices.Contains(merged, value) {
			merged = append(merged, value)
		}
	}
	sort.Strings(merged)
	return merged
}

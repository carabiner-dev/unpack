// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gradle

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
)

// Lockfiles Gradle writes beside a project's build file when dependency
// locking is on: one for the project's own configurations, and one for
// the classpath of its build script, which is its plugins.
const (
	LockFile            = "gradle.lockfile"
	BuildscriptLockFile = "buildscript-gradle.lockfile"
)

// Lock is a Gradle lockfile: the module versions the project's
// configurations resolved to, each with the configurations that have it.
// It is a flat list, with no edges between modules.
type Lock struct {
	Modules []*Module

	// Empty are the configurations that resolved to nothing.
	Empty []string
}

// Module is one locked module version.
type Module struct {
	Group   string
	Name    string
	Version string

	// Configurations are the configurations it is in, sorted:
	// compileClasspath, runtimeClasspath, testRuntimeClasspath, ...
	Configurations []string
}

// ReadLock reads a lockfile.
func ReadLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return ParseLock(data), nil
}

// ParseLock reads the contents of a lockfile: a line a module,
//
//	group:name:version=configuration,configuration
//
// comments starting with #, and a last line, empty=, listing the
// configurations with nothing in them. A line that is neither is passed
// over.
func ParseLock(data []byte) *Lock {
	lock := &Lock{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		configurations := splitList(value)
		if key == "empty" {
			lock.Empty = configurations
			continue
		}
		parts := strings.Split(key, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			continue
		}
		lock.Modules = append(lock.Modules, &Module{
			Group: parts[0], Name: parts[1], Version: parts[2], Configurations: configurations,
		})
	}
	sort.SliceStable(lock.Modules, func(i, j int) bool {
		a, b := lock.Modules[i], lock.Modules[j]
		return a.Group+":"+a.Name+":"+a.Version < b.Group+":"+b.Name+":"+b.Version
	})
	return lock
}

func splitList(value string) []string {
	items := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	slices.Sort(items)
	return items
}

// Role says what a module is to the project, read off the configurations
// it is in.
type Role int

const (
	// RoleRuntime is a module of a runtime classpath: it ships with the
	// project.
	RoleRuntime Role = iota

	// RoleCompileOnly is a module of a compile classpath and of no
	// runtime one: needed to compile, and provided by something else
	// when the project runs.
	RoleCompileOnly

	// RoleProcessor is a module only on an annotation processor path:
	// it runs in the compiler.
	RoleProcessor

	// RoleTest is a module only the tests have.
	RoleTest
)

// Suffixes of the names Gradle's plugins give their configurations. The
// Java plugin has compileClasspath, runtimeClasspath, annotationProcessor
// and, for the tests, the same with a test prefix; the plugins built on
// it prefix them with a source set or a variant
// (debugRuntimeClasspath, releaseUnitTestCompileClasspath).
const (
	suffixRuntime   = "runtimeclasspath"
	suffixCompile   = "compileclasspath"
	suffixProcessor = "annotationprocessor"
	markTest        = "test"
)

// Role returns what the module is to the project. The configurations
// outside the tests decide; a module with none is the tests' own.
//
// A configuration whose name says nothing, one a build defines itself, is
// taken as shipping with the project: a module is left out of the
// runtime only on the word of a name that says so.
func (m *Module) Role() Role {
	var runtime, compile, processor, other bool
	for _, configuration := range m.Configurations {
		name := strings.ToLower(configuration)
		switch {
		case strings.Contains(name, markTest):
		case strings.HasSuffix(name, suffixRuntime):
			runtime = true
		case strings.HasSuffix(name, suffixCompile):
			compile = true
		case strings.HasSuffix(name, suffixProcessor):
			processor = true
		default:
			other = true
		}
	}
	switch {
	case runtime || other:
		return RoleRuntime
	case compile:
		return RoleCompileOnly
	case processor:
		return RoleProcessor
	case len(m.Configurations) == 0:
		return RoleRuntime
	default:
		return RoleTest
	}
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pkgconf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// This file reads pkg-config files (.pc), in the format pkgconf documents
// in pc(5): comments, variables assigned as in a shell, and properties
// written as a keyword, a colon and a value. It reads what an inventory
// needs of them, the metadata and the dependency lists, and not the
// compiler and linker flags.

// Suffixes of a pkg-config file, and of one a build system fills in
// before installing it.
const (
	pcSuffix       = ".pc"
	templateSuffix = ".pc.in"
)

// File is what a pkg-config file says of its package.
type File struct {
	// ID is the name the package is asked for by: the name of its file,
	// without the suffix. Name is the label it gives itself, which is
	// often another: libssl.pc is named OpenSSL-libssl.
	ID   string
	Name string

	Description string
	Version     string
	URL         string

	// Source is where the sources were downloaded from, Maintainer who
	// to contact, and Copyright the copyright statements, one a line of
	// the file. They and the license are pkgconf's own additions to the
	// format.
	Source     string
	Maintainer string
	Copyright  []string

	// Licenses are the license expressions of the package; several are
	// meant joined by AND. LicenseFile is where the installed license
	// text is.
	Licenses    []string
	LicenseFile string

	// The dependency lists: what a user of the package needs with it
	// always, what it needs for static linking and header inclusion, for
	// static linking alone, and when used as a shared library alone.
	Requires         []Dependency
	RequiresPrivate  []Dependency
	RequiresInternal []Dependency
	RequiresShared   []Dependency

	// Provides are the other names the package answers to.
	Provides []Dependency

	// Unresolved lists the properties whose value holds something the
	// file does not settle: a placeholder a build system fills in
	// (@VERSION@) or a variable defined nowhere in the file. Such a
	// value is left out of the fields above.
	Unresolved []string

	// declared are the keywords the file has a property for, in lower
	// case, whatever became of their values.
	declared map[string]bool
}

// requiredKeywords are the properties a pkg-config file must have: the
// ones pkgconf refuses a file for lacking.
var requiredKeywords = []string{"name", "description", "version"}

// Valid says whether the file is a pkg-config file, by pkgconf's own
// test: it declares a Name, a Description and a Version. Their values may
// be placeholders, as a template's are.
//
// The suffix alone does not say. Other things are called .pc, the sources
// of Oracle's Pro*C among them, and they declare none of the three.
func (f *File) Valid() bool {
	return len(f.Missing()) == 0
}

// Missing returns the properties a pkg-config file must have that this
// one lacks, as pkgconf names them.
func (f *File) Missing() []string {
	missing := []string{}
	for _, keyword := range requiredKeywords {
		if !f.declared[keyword] {
			missing = append(missing, strings.ToUpper(keyword[:1])+keyword[1:])
		}
	}
	return missing
}

// Dependency is one entry of a dependency list: a package, and the
// versions of it that will do when the list says.
type Dependency struct {
	Name     string
	Operator string
	Version  string
}

// Constraint returns the versions that will do, as the file writes them
// (">= 1.2.3"), and nothing when any will.
func (d *Dependency) Constraint() string {
	if d.Operator == "" {
		return ""
	}
	return d.Operator + " " + d.Version
}

// ReadFile reads a pkg-config file.
func ReadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading pkg-config file: %w", err)
	}
	base := filepath.Base(path)
	id := strings.TrimSuffix(strings.TrimSuffix(base, templateSuffix), pcSuffix)
	return Parse(id, string(data)), nil
}

var (
	variableLine = regexp.MustCompile(`^([A-Za-z0-9_.]+)\s*=(.*)$`)
	propertyLine = regexp.MustCompile(`^([A-Za-z0-9_.]+)\s*:(.*)$`)

	// placeholder is what a build system replaces in a template:
	// @VERSION@ for autoconf and CMake.
	placeholder = regexp.MustCompile(`@[A-Za-z_][A-Za-z0-9_]*@`)
	reference   = regexp.MustCompile(`\$\{([^}]*)\}`)
)

// Parse reads the contents of a pkg-config file. It does not fail: a
// line that is neither a variable nor a property is passed over, as
// pkgconf itself only warns of them.
func Parse(id, content string) *File {
	file := &File{ID: id, declared: map[string]bool{}}
	variables := map[string]string{}

	for _, line := range logicalLines(content) {
		if match := variableLine.FindStringSubmatch(line); match != nil {
			// A variable holds its value expanded when it can be, and
			// as written otherwise, so that what uses it is seen to be
			// unresolved too.
			value, _ := expand(strings.TrimSpace(match[2]), variables)
			variables[match[1]] = value
			continue
		}
		match := propertyLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		keyword := match[1]
		value, resolved := expand(strings.TrimSpace(match[2]), variables)
		if !resolved {
			file.Unresolved = append(file.Unresolved, keyword)
		}
		file.declared[strings.ToLower(keyword)] = true
		file.set(keyword, value, resolved)
	}
	return file
}

// logicalLines splits the content into lines, without their comments, a
// line ending in a backslash carrying on with the next.
func logicalLines(content string) []string {
	lines := []string{}
	var pending strings.Builder
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := stripComment(raw)
		if continued, ok := strings.CutSuffix(strings.TrimRight(line, " \t"), `\`); ok {
			pending.WriteString(continued)
			pending.WriteString(" ")
			continue
		}
		pending.WriteString(line)
		if joined := strings.TrimSpace(pending.String()); joined != "" {
			lines = append(lines, joined)
		}
		pending.Reset()
	}
	if joined := strings.TrimSpace(pending.String()); joined != "" {
		lines = append(lines, joined)
	}
	return lines
}

// stripComment removes a comment: what follows a # that is not escaped.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '#':
			return line[:i]
		}
	}
	return line
}

// expand replaces the variable references of a value with the variables
// of the file, and says whether the result is settled: not when it
// refers to a variable the file does not define, or holds a placeholder.
func expand(value string, variables map[string]string) (string, bool) {
	const literal = "\x00"
	value = strings.ReplaceAll(value, "$${", literal)

	resolved := true
	value = reference.ReplaceAllStringFunc(value, func(ref string) string {
		name := reference.FindStringSubmatch(ref)[1]
		replacement, ok := variables[name]
		if !ok {
			resolved = false
			return ref
		}
		return replacement
	})
	if placeholder.MatchString(value) || strings.Contains(value, "${") {
		resolved = false
	}
	return strings.ReplaceAll(value, literal, "${"), resolved
}

// set records a property. Keywords are matched whatever their case, as
// pkgconf does. A value that is not settled is kept only where part of
// it still says something: a dependency list, whose settled entries are
// read.
func (f *File) set(keyword, value string, resolved bool) {
	literal := func(target *string) {
		if resolved {
			*target = value
		}
	}
	switch strings.ToLower(keyword) {
	case "name":
		literal(&f.Name)
	case "description":
		literal(&f.Description)
	case "version":
		literal(&f.Version)
	case "url":
		literal(&f.URL)
	case "source":
		literal(&f.Source)
	case "maintainer":
		literal(&f.Maintainer)
	case "license.file":
		literal(&f.LicenseFile)
	case "copyright":
		if resolved && value != "" {
			f.Copyright = append(f.Copyright, value)
		}
	case "license":
		if resolved && value != "" {
			f.Licenses = append(f.Licenses, value)
		}
	case "requires":
		f.Requires = append(f.Requires, ParseDependencies(value)...)
	case "requires.private":
		f.RequiresPrivate = append(f.RequiresPrivate, ParseDependencies(value)...)
	case "requires.internal":
		f.RequiresInternal = append(f.RequiresInternal, ParseDependencies(value)...)
	case "requires.shared":
		f.RequiresShared = append(f.RequiresShared, ParseDependencies(value)...)
	case "provides":
		f.Provides = append(f.Provides, ParseDependencies(value)...)
	}
}

var (
	packageName    = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	packageVersion = regexp.MustCompile(`^[A-Za-z0-9._+~^:-]+$`)
	operators      = []string{"<=", ">=", "!=", "<", ">", "="}
)

// ParseDependencies reads a dependency list: packages separated by
// whitespace or commas, each a name and optionally an operator and a
// version, with or without spaces around the operator.
//
// An entry that is no package name is left out, with the operator and
// version that follow it: that is what a placeholder nobody filled in
// looks like.
func ParseDependencies(list string) []Dependency {
	// Operators are set apart so that "zlib>=1.2" reads as "zlib >= 1.2".
	fields := strings.Fields(strings.ReplaceAll(list, ",", " "))
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		tokens = append(tokens, splitOperators(field)...)
	}

	deps := []Dependency{}
	for i := 0; i < len(tokens); i++ {
		name := tokens[i]
		if isOperator(name) {
			// An operator with no name before it: skip its version.
			i++
			continue
		}
		dep := Dependency{Name: name}
		if i+2 < len(tokens) && isOperator(tokens[i+1]) {
			dep.Operator, dep.Version = tokens[i+1], tokens[i+2]
			i += 2
		} else if i+1 < len(tokens) && isOperator(tokens[i+1]) {
			i++
		}
		if !packageName.MatchString(dep.Name) {
			continue
		}
		if dep.Operator != "" && !packageVersion.MatchString(dep.Version) {
			dep.Operator, dep.Version = "", ""
		}
		deps = append(deps, dep)
	}
	return deps
}

func isOperator(token string) bool {
	return slices.Contains(operators, token)
}

// splitOperators sets the operators of a field apart from what is around
// them.
func splitOperators(field string) []string {
	parts := []string{}
	for field != "" {
		at, length := -1, 0
		for _, op := range operators {
			if i := strings.Index(field, op); i >= 0 && (at < 0 || i < at || (i == at && len(op) > length)) {
				at, length = i, len(op)
			}
		}
		if at < 0 {
			parts = append(parts, field)
			break
		}
		if at > 0 {
			parts = append(parts, field[:at])
		}
		parts = append(parts, field[at:at+length])
		field = field[at+length:]
	}
	return parts
}

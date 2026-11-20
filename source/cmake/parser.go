// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmake

import (
	"fmt"
	"strings"
)

// This file reads the CMake language as far as an inventory needs it: a
// file is a sequence of command invocations, each a name and a list of
// arguments. Nothing is evaluated here.

// Command is one command invocation of a CMake file.
type Command struct {
	// Name is the command's name in lower case: CMake does not tell
	// find_package from FIND_PACKAGE.
	Name string
	Args []Argument
	Line int
}

// Argument is one argument of a command.
type Argument struct {
	Value string

	// Quoted says the argument was written in quotes or brackets, which
	// makes it one value whatever it holds: a quoted REQUIRED is a string
	// and not a keyword, and a quoted list is not split.
	Quoted bool
}

// Values returns the arguments' values.
func (c *Command) Values() []string {
	values := make([]string, len(c.Args))
	for i := range c.Args {
		values[i] = c.Args[i].Value
	}
	return values
}

// parser walks the text of a CMake file.
type parser struct {
	src  string
	pos  int
	line int
}

// Parse reads the commands of a CMake file. It stops with an error at
// text that is not CMake, with the commands read up to there: a file with
// a mistake at its end still says what came before.
func Parse(src string) ([]Command, error) {
	p := &parser{src: src, line: 1}
	commands := []Command{}
	for {
		p.skipSpace(true)
		if p.pos >= len(p.src) {
			return commands, nil
		}
		command, err := p.command()
		if err != nil {
			return commands, err
		}
		commands = append(commands, command)
	}
}

// skipSpace skips whitespace and comments, across lines when told to.
func (p *parser) skipSpace(newlines bool) {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\n':
			if !newlines {
				return
			}
			p.line++
			p.pos++
		case ' ', '\t', '\r':
			p.pos++
		case '#':
			p.comment()
		default:
			return
		}
	}
}

// comment skips a comment: a bracket comment, which may span lines, or
// the rest of the line.
func (p *parser) comment() {
	p.pos++ // the #
	if _, ok := p.bracket(); ok {
		return
	}
	for p.pos < len(p.src) && p.src[p.pos] != '\n' {
		p.pos++
	}
}

// bracket reads a bracket argument, [[...]] or [=[...]=] with any number
// of equal signs, when one starts here.
func (p *parser) bracket() (string, bool) {
	if p.pos >= len(p.src) || p.src[p.pos] != '[' {
		return "", false
	}
	i := p.pos + 1
	for i < len(p.src) && p.src[i] == '=' {
		i++
	}
	if i >= len(p.src) || p.src[i] != '[' {
		return "", false
	}
	closing := "]" + strings.Repeat("=", i-p.pos-1) + "]"
	start := i + 1
	end := strings.Index(p.src[start:], closing)
	if end < 0 {
		return "", false
	}
	content := p.src[start : start+end]
	p.line += strings.Count(content, "\n")
	p.pos = start + end + len(closing)
	// A newline right after the opening bracket is not part of the value.
	content = strings.TrimPrefix(strings.TrimPrefix(content, "\r"), "\n")
	return content, true
}

// command reads one command invocation.
func (p *parser) command() (Command, error) {
	start := p.pos
	for p.pos < len(p.src) && isIdentifier(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return Command{}, fmt.Errorf("line %d: expected a command, found %q", p.line, p.src[p.pos])
	}
	command := Command{Name: strings.ToLower(p.src[start:p.pos]), Line: p.line}

	p.skipSpace(false)
	if p.pos >= len(p.src) || p.src[p.pos] != '(' {
		return Command{}, fmt.Errorf("line %d: expected ( after %s", p.line, command.Name)
	}
	p.pos++

	// Parentheses nest inside the arguments, as in if((A) AND (B)). They
	// are kept as arguments of their own.
	depth := 1
	for {
		p.skipSpace(true)
		if p.pos >= len(p.src) {
			return Command{}, fmt.Errorf("line %d: %s( is not closed", command.Line, command.Name)
		}
		switch p.src[p.pos] {
		case '(':
			depth++
			p.pos++
			command.Args = append(command.Args, Argument{Value: "("})
		case ')':
			depth--
			p.pos++
			if depth == 0 {
				return command, nil
			}
			command.Args = append(command.Args, Argument{Value: ")"})
		case '"':
			command.Args = append(command.Args, Argument{Value: p.quoted(), Quoted: true})
		default:
			if value, ok := p.bracket(); ok {
				command.Args = append(command.Args, Argument{Value: value, Quoted: true})
				continue
			}
			// An unquoted argument holding semicolons is a list.
			for _, value := range strings.Split(p.unquoted(), ";") {
				if value != "" {
					command.Args = append(command.Args, Argument{Value: value})
				}
			}
		}
	}
}

// quoted reads a quoted argument, the opening quote included.
func (p *parser) quoted() string {
	p.pos++
	var value strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return value.String()
		case c == '\\' && p.pos+1 < len(p.src):
			p.pos++
			next := p.src[p.pos]
			switch next {
			case 'n':
				value.WriteByte('\n')
			case 't':
				value.WriteByte('\t')
			case 'r':
				value.WriteByte('\r')
			case '\n':
				// A line continuation.
				p.line++
			case '$', ';':
				// Kept escaped: they are not a reference or a
				// separator.
				value.WriteByte('\\')
				value.WriteByte(next)
			default:
				value.WriteByte(next)
			}
			p.pos++
		default:
			if c == '\n' {
				p.line++
			}
			value.WriteByte(c)
			p.pos++
		}
	}
	return value.String()
}

// unquoted reads an unquoted argument: up to whitespace, a parenthesis, a
// quote or a comment. A variable reference in it may hold what would end
// it elsewhere, as in ${A}(x) which CMake does not split either.
func (p *parser) unquoted() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\\' && p.pos+1 < len(p.src) {
			p.pos += 2
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '(' || c == ')' || c == '"' || c == '#' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		// Nothing an argument can start with: step over it so the
		// caller cannot loop on it.
		p.pos++
	}
	return p.src[start:p.pos]
}

func isIdentifier(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

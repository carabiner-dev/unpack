// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"strings"
)

// This file implements environment markers (PEP 508), the conditions Python
// dependency data hangs off relationships: colorama is a dependency of click
// only where sys_platform == 'win32'. A lockfile resolves for every
// environment at once, so reading one for a concrete target means evaluating
// these markers against it.
//
// The grammar is small: comparisons between environment variables and quoted
// strings, joined by "and" and "or" (and binding tighter), with parentheses.
// There is no unary not; negation exists only as "not in".

// Marker is a parsed environment marker, ready to evaluate.
type Marker struct {
	root markerNode
}

// ParseMarker parses an environment marker expression such as
// "python_full_version < '3.11' and sys_platform == 'linux'".
func ParseMarker(s string) (*Marker, error) {
	tokens, err := tokenizeMarker(s)
	if err != nil {
		return nil, fmt.Errorf("parsing marker %q: %w", s, err)
	}
	p := &markerParser{tokens: tokens}
	root, err := p.parseOr()
	if err != nil {
		return nil, fmt.Errorf("parsing marker %q: %w", s, err)
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("parsing marker %q: unexpected %q", s, p.tokens[p.pos].text)
	}
	return &Marker{root: root}, nil
}

// Eval says whether the marker holds in the given environment.
func (m *Marker) Eval(env *Environment) (bool, error) {
	return m.root.eval(env)
}

// markerNode is a node of the parsed expression tree.
type markerNode interface {
	eval(env *Environment) (bool, error)
}

// junction is an "and" or "or" over two or more terms.
type junction struct {
	all   bool // true for and, false for or
	terms []markerNode
}

func (j *junction) eval(env *Environment) (bool, error) {
	for _, term := range j.terms {
		holds, err := term.eval(env)
		if err != nil {
			return false, err
		}
		if holds != j.all {
			return holds, nil
		}
	}
	return j.all, nil
}

// comparison is a single operator between two operands, each an environment
// variable or a quoted literal.
type comparison struct {
	left, right operand
	op          string
}

// operand is one side of a comparison.
type operand struct {
	text    string
	literal bool // quoted string rather than an environment variable
}

func (c *comparison) eval(env *Environment) (bool, error) {
	// The extra variable is special: it holds the set of enabled extras,
	// and equality on it is membership.
	if handled, holds, err := c.evalExtra(env); handled {
		return holds, err
	}

	left, err := c.left.value(env)
	if err != nil {
		return false, err
	}
	right, err := c.right.value(env)
	if err != nil {
		return false, err
	}

	switch c.op {
	case "in":
		return strings.Contains(right, left), nil
	case "not in":
		return !strings.Contains(right, left), nil
	case "===":
		return left == right, nil
	}

	// Comparisons are version comparisons when both operands parse as
	// versions, and string comparisons otherwise, per the spec.
	if lv, err := ParseVersion(left); err == nil {
		if holds, ok := versionCompare(lv, right, c.op); ok {
			return holds, nil
		}
	}
	return stringCompare(left, right, c.op), nil
}

// evalExtra handles a comparison whose variable side is "extra". Equality
// means membership in the enabled set: with extras {"color"}, both
// extra == 'color' holds and extra != 'cli' holds.
func (c *comparison) evalExtra(env *Environment) (handled, holds bool, err error) {
	variable, literal := c.left, c.right
	if literal.text == "extra" && !literal.literal {
		variable, literal = c.right, c.left
	}
	if variable.literal || variable.text != "extra" || !literal.literal {
		return false, false, nil
	}

	name := NormalizeName(literal.text)
	switch c.op {
	case "==":
		return true, env.hasExtra(name), nil
	case "!=":
		return true, !env.hasExtra(name), nil
	default:
		return true, false, fmt.Errorf("operator %q does not apply to extra", c.op)
	}
}

// value resolves the operand to the string the comparison works on.
func (o *operand) value(env *Environment) (string, error) {
	if o.literal {
		return o.text, nil
	}
	return env.lookup(o.text)
}

// versionCompare applies op between a parsed version and the right operand.
// The second return value is false when the right side is not a version, in
// which case the comparison falls back to strings.
func versionCompare(left *Version, right, op string) (holds, ok bool) {
	// A trailing .* is a prefix match, valid only with equality.
	if prefix, isWild := strings.CutSuffix(right, ".*"); isWild {
		pv, err := ParseVersion(prefix)
		if err != nil {
			return false, false
		}
		switch op {
		case "==":
			return left.matchesPrefix(pv), true
		case "!=":
			return !left.matchesPrefix(pv), true
		default:
			return false, false
		}
	}

	rv, err := ParseVersion(right)
	if err != nil {
		return false, false
	}

	// Compatible release: ~= X.Y.Z means >= X.Y.Z and == X.Y.*.
	if op == "~=" {
		if len(rv.Release) < 2 {
			return false, false
		}
		prefix := &Version{Epoch: rv.Epoch, Release: rv.Release[:len(rv.Release)-1]}
		return left.Compare(rv) >= 0 && left.matchesPrefix(prefix), true
	}

	c := left.Compare(rv)
	switch op {
	case "==":
		return c == 0, true
	case "!=":
		return c != 0, true
	case "<":
		return c < 0, true
	case "<=":
		return c <= 0, true
	case ">":
		return c > 0, true
	case ">=":
		return c >= 0, true
	default:
		return false, false
	}
}

func stringCompare(left, right, op string) bool {
	switch op {
	case "==":
		return left == right
	case "!=":
		return left != right
	case "<":
		return left < right
	case "<=":
		return left <= right
	case ">":
		return left > right
	case ">=":
		return left >= right
	default: // ~= between non-versions holds for nothing
		return false
	}
}

// markerParser is a recursive-descent parser over the token stream.
type markerParser struct {
	tokens []markerToken
	pos    int
}

func (p *markerParser) parseOr() (markerNode, error) {
	terms := []markerNode{}
	for {
		term, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
		if !p.accept("or") {
			break
		}
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return &junction{all: false, terms: terms}, nil
}

func (p *markerParser) parseAnd() (markerNode, error) {
	terms := []markerNode{}
	for {
		term, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
		if !p.accept("and") {
			break
		}
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return &junction{all: true, terms: terms}, nil
}

func (p *markerParser) parseAtom() (markerNode, error) {
	if p.accept("(") {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.accept(")") {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		return inner, nil
	}

	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	op, err := p.parseOperator()
	if err != nil {
		return nil, err
	}
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	return &comparison{left: left, op: op, right: right}, nil
}

func (p *markerParser) parseOperand() (operand, error) {
	if p.pos >= len(p.tokens) {
		return operand{}, fmt.Errorf("expected an operand, found the end of the marker")
	}
	tok := p.tokens[p.pos]
	switch tok.kind {
	case tokenString:
		p.pos++
		return operand{text: tok.text, literal: true}, nil
	case tokenWord:
		p.pos++
		return operand{text: tok.text}, nil
	case tokenOperator, tokenParen:
		return operand{}, fmt.Errorf("expected an operand, found %q", tok.text)
	default:
		return operand{}, fmt.Errorf("expected an operand, found %q", tok.text)
	}
}

func (p *markerParser) parseOperator() (string, error) {
	if p.pos >= len(p.tokens) {
		return "", fmt.Errorf("expected an operator, found the end of the marker")
	}
	tok := p.tokens[p.pos]
	switch {
	case tok.kind == tokenOperator:
		p.pos++
		return tok.text, nil
	case tok.kind == tokenWord && tok.text == "in":
		p.pos++
		return "in", nil
	case tok.kind == tokenWord && tok.text == "not":
		p.pos++
		if !p.accept("in") {
			return "", fmt.Errorf(`"not" must be followed by "in"`)
		}
		return "not in", nil
	default:
		return "", fmt.Errorf("expected an operator, found %q", tok.text)
	}
}

// accept consumes the next token when it is the given word or symbol.
func (p *markerParser) accept(text string) bool {
	if p.pos < len(p.tokens) && p.tokens[p.pos].text == text {
		p.pos++
		return true
	}
	return false
}

type markerTokenKind int

const (
	tokenWord markerTokenKind = iota
	tokenString
	tokenOperator
	tokenParen
)

type markerToken struct {
	kind markerTokenKind
	text string
}

// markerOperators lists the comparison operators, longest first so the
// tokenizer never reads === as == followed by =.
var markerOperators = []string{"===", "==", "!=", "<=", ">=", "~=", "<", ">"}

func tokenizeMarker(s string) ([]markerToken, error) {
	tokens := []markerToken{}
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			tokens = append(tokens, markerToken{kind: tokenParen, text: string(c)})
			i++
		case c == '\'' || c == '"':
			end := strings.IndexByte(s[i+1:], c)
			if end < 0 {
				return nil, fmt.Errorf("unterminated string")
			}
			tokens = append(tokens, markerToken{kind: tokenString, text: s[i+1 : i+1+end]})
			i += end + 2
		case isWordByte(c):
			start := i
			for i < len(s) && isWordByte(s[i]) {
				i++
			}
			tokens = append(tokens, markerToken{kind: tokenWord, text: s[start:i]})
		default:
			op := matchOperator(s[i:])
			if op == "" {
				return nil, fmt.Errorf("unexpected character %q", c)
			}
			tokens = append(tokens, markerToken{kind: tokenOperator, text: op})
			i += len(op)
		}
	}
	return tokens, nil
}

func matchOperator(s string) string {
	for _, op := range markerOperators {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	return ""
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file implements Python version ordering (PEP 440), which environment
// markers need: python_full_version < '3.11' is a version comparison, not a
// string one, and the difference shows on real data ("3.9" sorts after
// "3.11" as a string).

// versionPattern is the canonical PEP 440 version grammar, from the spec's
// appendix, without the surrounding whitespace and optional v prefix, which
// ParseVersion strips itself.
var versionPattern = regexp.MustCompile(`(?i)^` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<preL>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<preN>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<postN1>[0-9]+))|(?:[-_.]?(?:post|rev|r)[-_.]?(?P<postN2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?dev[-_.]?(?P<devN>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?` +
	`$`)

// localSeparators splits the segments of a local version label.
var localSeparators = regexp.MustCompile(`[-_.]`)

// Version is a parsed PEP 440 version.
type Version struct {
	Epoch   int
	Release []int

	// Pre is the pre-release phase, in order: "a" < "b" < "rc". The long
	// spellings (alpha, beta, c, pre, preview) normalize into those three.
	Pre    int
	PreN   int
	HasPre bool

	Post    int
	HasPost bool

	Dev    int
	HasDev bool

	Local string
}

// preOrder ranks the pre-release spellings PEP 440 admits.
var preOrder = map[string]int{
	"a": 1, "alpha": 1,
	"b": 2, "beta": 2,
	"rc": 3, "c": 3, "pre": 3, "preview": 3,
}

// ParseVersion parses a PEP 440 version string.
func ParseVersion(s string) (*Version, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "v")

	m := versionPattern.FindStringSubmatch(trimmed)
	if m == nil {
		return nil, fmt.Errorf("%q is not a valid Python version", s)
	}
	group := func(name string) string {
		return m[versionPattern.SubexpIndex(name)]
	}

	v := &Version{}
	if e := group("epoch"); e != "" {
		v.Epoch = mustAtoi(e)
	}
	for _, part := range strings.Split(group("release"), ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid Python version: release segment %q", s, part)
		}
		v.Release = append(v.Release, n)
	}

	// A phase present without a number is that phase's zero: 1.0a is 1.0a0.
	if group("pre") != "" {
		v.HasPre = true
		v.Pre = preOrder[group("preL")]
		v.PreN = mustAtoi(group("preN"))
	}
	if group("post") != "" {
		v.HasPost = true
		v.Post = mustAtoi(group("postN1") + group("postN2"))
	}
	if group("dev") != "" {
		v.HasDev = true
		v.Dev = mustAtoi(group("devN"))
	}
	v.Local = group("local")
	return v, nil
}

// Compare orders two versions per PEP 440: -1, 0 or 1 as v sorts before,
// with or after o. Trailing zeros in the release are insignificant
// (1.0 == 1.0.0), a dev release sorts before pre-releases, pre-releases
// before the final, the final before post-releases, and a local version
// after the same version without one.
func (v *Version) Compare(o *Version) int {
	if c := cmpInt(v.Epoch, o.Epoch); c != 0 {
		return c
	}
	if c := cmpRelease(v.Release, o.Release); c != 0 {
		return c
	}
	if c := cmpTriple(v.preKey(), o.preKey()); c != 0 {
		return c
	}
	if c := cmpTriple(v.postKey(), o.postKey()); c != 0 {
		return c
	}
	if c := cmpTriple(v.devKey(), o.devKey()); c != 0 {
		return c
	}
	return cmpLocal(v.Local, o.Local)
}

// preKey ranks the pre-release phase: dev-only < a < b < rc < final.
func (v *Version) preKey() [3]int {
	switch {
	case !v.HasPre && !v.HasPost && v.HasDev:
		return [3]int{0, 0, 0}
	case v.HasPre:
		return [3]int{1, v.Pre, v.PreN}
	default:
		return [3]int{2, 0, 0}
	}
}

// postKey ranks the post-release phase: none < post.
func (v *Version) postKey() [3]int {
	if v.HasPost {
		return [3]int{1, v.Post, 0}
	}
	return [3]int{0, 0, 0}
}

// devKey ranks the dev phase: dev < none.
func (v *Version) devKey() [3]int {
	if v.HasDev {
		return [3]int{0, v.Dev, 0}
	}
	return [3]int{1, 0, 0}
}

// mustAtoi converts a string the version grammar has already vouched for:
// it matched a digit run, or is empty, which is a phase's zero.
func mustAtoi(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("the version grammar admitted a non-number %q", s))
	}
	return n
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpTriple(a, b [3]int) int {
	for i := range a {
		if c := cmpInt(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

// cmpRelease compares release segments element-wise, padding the shorter
// with zeros, so 1.0 and 1.0.0 are the same version.
func cmpRelease(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if c := cmpInt(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

// cmpLocal orders local version labels: absent sorts first, then segment by
// segment, where numeric segments compare numerically and sort after
// alphanumeric ones, and a label that is a prefix of another sorts first.
func cmpLocal(a, b string) int {
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}

	as, bs := localSeparators.Split(a, -1), localSeparators.Split(b, -1)
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		if c := cmpLocalSegment(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return 0
}

func cmpLocalSegment(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return cmpInt(an, bn)
	case aerr == nil:
		return 1 // numeric segments sort after alphanumeric ones
	case berr == nil:
		return -1
	default:
		return strings.Compare(a, b)
	}
}

// matchesPrefix says whether v matches a wildcard version such as 3.11.*:
// the releases agree on every segment the prefix states. Pre, post and dev
// segments do not defeat a prefix match, per the spec.
func (v *Version) matchesPrefix(prefix *Version) bool {
	if v.Epoch != prefix.Epoch {
		return false
	}
	for i, want := range prefix.Release {
		have := 0
		if i < len(v.Release) {
			have = v.Release[i]
		}
		if have != want {
			return false
		}
	}
	return true
}

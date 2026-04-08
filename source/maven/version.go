// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Coordinate uniquely identifies a Maven artifact.
type Coordinate struct {
	GroupID    string
	ArtifactID string
	Version    string
	Classifier string
	Type       string
}

// String returns "groupId:artifactId:version".
func (c Coordinate) String() string {
	return fmt.Sprintf("%s:%s:%s", c.GroupID, c.ArtifactID, c.Version)
}

// PURL returns the Package URL for this coordinate.
func (c *Coordinate) PURL() string {
	purl := fmt.Sprintf("pkg:maven/%s/%s", c.GroupID, c.ArtifactID)
	if c.Version != "" {
		purl += "@" + c.Version
	}
	return purl
}

// Key returns "groupId:artifactId" for mediation lookups.
func (c *Coordinate) Key() string {
	return c.GroupID + ":" + c.ArtifactID
}

// qualifierRank returns the ordering rank for known Maven qualifiers.
// Lower values sort earlier. Unknown qualifiers get a high rank.
func qualifierRank(q string) int {
	switch strings.ToLower(q) {
	case "alpha", "a":
		return 1
	case "beta", "b":
		return 2
	case "milestone", "m":
		return 3
	case "rc", "cr":
		return 4
	case "snapshot":
		return 5
	case "", "final", "ga", "release":
		return 6
	case "sp":
		return 7
	default:
		return 8
	}
}

// versionItem represents one segment of a parsed Maven version.
// It can be either numeric or string-typed.
type versionItem struct {
	numeric   int
	qualifier string
	isNumeric bool
}

// parseVersionItems splits a Maven version string into comparable items.
// Maven version strings are split on '.', '-', and digit/letter transitions.
func parseVersionItems(s string) []versionItem {
	if s == "" {
		return nil
	}

	var items []versionItem
	var current strings.Builder
	prevIsDigit := false

	flush := func() {
		tok := current.String()
		current.Reset()
		if tok == "" {
			return
		}
		if n, err := strconv.Atoi(tok); err == nil {
			items = append(items, versionItem{numeric: n, isNumeric: true})
		} else {
			items = append(items, versionItem{qualifier: tok})
		}
	}

	for i, ch := range s {
		isDigit := unicode.IsDigit(ch)
		if ch == '.' || ch == '-' {
			flush()
			prevIsDigit = false
			continue
		}
		// Split on digit<->letter transitions
		if i > 0 && current.Len() > 0 && isDigit != prevIsDigit {
			flush()
		}
		current.WriteRune(ch)
		prevIsDigit = isDigit
	}
	flush()
	return items
}

// CompareVersions compares two Maven version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareVersions(a, b string) int {
	itemsA := parseVersionItems(a)
	itemsB := parseVersionItems(b)

	maxLen := len(itemsA)
	if len(itemsB) > maxLen {
		maxLen = len(itemsB)
	}

	for i := range maxLen {
		var ia, ib versionItem
		if i < len(itemsA) {
			ia = itemsA[i]
		}
		if i < len(itemsB) {
			ib = itemsB[i]
		}

		cmp := compareItems(ia, ib)
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

// compareItems compares two version items.
func compareItems(a, b versionItem) int {
	// Both numeric: compare as integers
	if a.isNumeric && b.isNumeric {
		return intCmp(a.numeric, b.numeric)
	}

	// Both qualifiers: compare by rank then lexically
	if !a.isNumeric && !b.isNumeric {
		rankA := qualifierRank(a.qualifier)
		rankB := qualifierRank(b.qualifier)
		if rankA != rankB {
			return intCmp(rankA, rankB)
		}
		// Same rank bucket (both unknown): compare lexically
		if rankA == 8 {
			return strings.Compare(strings.ToLower(a.qualifier), strings.ToLower(b.qualifier))
		}
		return 0
	}

	// One is numeric, one is qualifier (or missing)
	// A missing item is equivalent to 0 (numeric) or "" (release qualifier)
	if a.isNumeric && !b.isNumeric {
		// numeric vs qualifier: if qualifier is release-equivalent, numeric wins on value
		if b.qualifier == "" {
			// missing item = 0, compare a.numeric to 0
			return intCmp(a.numeric, 0)
		}
		// A number is always "newer" than a qualifier
		return 1
	}

	// qualifier vs numeric
	if a.qualifier == "" {
		return intCmp(0, b.numeric)
	}
	return -1
}

func intCmp(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// VersionRange represents a Maven version range constraint.
type VersionRange struct {
	LowerBound     string
	UpperBound     string
	LowerInclusive bool
	UpperInclusive bool
}

// IsVersionRange returns true if the string looks like a Maven version range.
func IsVersionRange(s string) bool {
	return strings.HasPrefix(s, "[") || strings.HasPrefix(s, "(")
}

// ParseVersionRange parses a Maven version range string.
// Supported formats: [1.0,2.0), [1.0], (,1.0], [1.0,), etc.
func ParseVersionRange(s string) (*VersionRange, error) {
	if len(s) < 2 {
		return nil, fmt.Errorf("invalid version range: %q", s)
	}

	first := s[0]
	last := s[len(s)-1]

	var lowerInclusive, upperInclusive bool
	switch first {
	case '[':
		lowerInclusive = true
	case '(':
		lowerInclusive = false
	default:
		return nil, fmt.Errorf("invalid version range start: %q", s)
	}
	switch last {
	case ']':
		upperInclusive = true
	case ')':
		upperInclusive = false
	default:
		return nil, fmt.Errorf("invalid version range end: %q", s)
	}

	inner := s[1 : len(s)-1]
	parts := strings.SplitN(inner, ",", 2)

	vr := &VersionRange{
		LowerInclusive: lowerInclusive,
		UpperInclusive: upperInclusive,
	}

	if len(parts) == 1 {
		// Exact version: [1.0]
		vr.LowerBound = strings.TrimSpace(parts[0])
		vr.UpperBound = vr.LowerBound
		vr.LowerInclusive = true
		vr.UpperInclusive = true
	} else {
		vr.LowerBound = strings.TrimSpace(parts[0])
		vr.UpperBound = strings.TrimSpace(parts[1])
	}

	return vr, nil
}

// Contains returns true if the given version satisfies this range.
func (vr *VersionRange) Contains(version string) bool {
	if vr.LowerBound != "" {
		cmp := CompareVersions(version, vr.LowerBound)
		if vr.LowerInclusive && cmp < 0 {
			return false
		}
		if !vr.LowerInclusive && cmp <= 0 {
			return false
		}
	}

	if vr.UpperBound != "" {
		cmp := CompareVersions(version, vr.UpperBound)
		if vr.UpperInclusive && cmp > 0 {
			return false
		}
		if !vr.UpperInclusive && cmp >= 0 {
			return false
		}
	}

	return true
}

// SelectVersion picks the highest version from candidates that satisfies the range.
func (vr *VersionRange) SelectVersion(candidates []string) string {
	var best string
	for _, v := range candidates {
		if !vr.Contains(v) {
			continue
		}
		if best == "" || CompareVersions(v, best) > 0 {
			best = v
		}
	}
	return best
}

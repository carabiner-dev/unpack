// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import "strings"

// This file checks a version against a version constraint: the specifier
// of a requirement (PEP 440, ">=2,<3") and the constraints Poetry writes
// in a lock and reads from a manifest, which are the same clauses plus "*"
// for any version, "||" between alternatives, and its own caret and tilde
// ranges ("^1.2", "~1.2"). Nothing here resolves anything: it only tells
// apart lock entries that are already resolved.

// satisfies reports whether a version meets a constraint. The second
// return value is false when either cannot be read, in which case the
// constraint says nothing and the caller must not narrow by it.
func satisfies(version, constraint string) (holds, known bool) {
	parsed, err := ParseVersion(version)
	if err != nil {
		return false, false
	}

	// A requirement may wrap its specifier in parentheses.
	constraint = strings.TrimSpace(constraint)
	constraint = strings.TrimSuffix(strings.TrimPrefix(constraint, "("), ")")

	for _, alternative := range strings.Split(constraint, "||") {
		all := true
		for _, clause := range strings.Split(alternative, ",") {
			clause = strings.TrimSpace(clause)
			if clause == "" || clause == "*" {
				continue
			}
			if upper, isRange := poetryRangeUpper(clause); isRange {
				clauseHolds, ok := withinPoetryRange(parsed, clause[1:], upper)
				if !ok {
					return false, false
				}
				all = all && clauseHolds
				continue
			}

			op := matchOperator(clause)
			operand := strings.TrimSpace(strings.TrimPrefix(clause, op))
			switch op {
			case "":
				// A bare version names exactly that version.
				op = "=="
			case opArbitraryEqual:
				op = "=="
			}
			clauseHolds, ok := versionCompare(parsed, operand, op)
			if !ok {
				return false, false
			}
			all = all && clauseHolds
		}
		if all {
			return true, true
		}
	}
	return false, true
}

// poetryRangeUpper recognizes Poetry's caret and tilde ranges and says
// which release component bounds them from above. Both start at the
// version written. A caret range allows what does not change the leftmost
// non-zero component: "^1.2.3" stays below 2, "^0.2.3" below 0.3, and
// "^0.0.3" below 0.0.4. A tilde range allows the last component written to
// grow, the minor one at most: "~1.2.3" and "~1.2" stay below 1.3, "~1"
// below 2. PEP 440's "~=" is not one of these.
func poetryRangeUpper(clause string) (upper func(release []int) int, isRange bool) {
	switch {
	case strings.HasPrefix(clause, "^"):
		return func(release []int) int {
			for i, part := range release {
				if part != 0 {
					return i
				}
			}
			return len(release) - 1
		}, true
	case strings.HasPrefix(clause, "~") && !strings.HasPrefix(clause, "~="):
		return func(release []int) int {
			return min(1, len(release)-1)
		}, true
	default:
		return nil, false
	}
}

// withinPoetryRange reports whether a version is at or above the one a
// caret or tilde range is written with and below the bound it implies.
func withinPoetryRange(version *Version, written string, upper func(release []int) int) (holds, known bool) {
	lower, err := ParseVersion(strings.TrimSpace(written))
	if err != nil || len(lower.Release) == 0 {
		return false, false
	}
	at := upper(lower.Release)
	bound := &Version{Epoch: lower.Epoch, Release: append(append([]int{}, lower.Release[:at]...), lower.Release[at]+1)}
	return version.Compare(lower) >= 0 && version.Compare(bound) < 0, true
}

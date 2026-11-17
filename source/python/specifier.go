// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import "strings"

// This file checks a version against a version constraint: the specifier
// of a requirement (PEP 440, ">=2,<3") and the constraints a poetry.lock
// writes, which are the same clauses plus "*" for any version and "||"
// between alternatives. Nothing here resolves anything: it only tells
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

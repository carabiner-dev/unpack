// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSatisfies(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		version    string
		constraint string
		holds      bool
		known      bool
	}{
		// No constraint, or any version.
		{"1.5", "", true, true},
		{"1.5", "*", true, true},

		// Single clauses.
		{"2.5", ">=2", true, true},
		{"1.5", ">=2", false, true},
		{"1.5", "<2", true, true},
		{"1.5", "==1.5", true, true},
		{"1.5", "===1.5", true, true},
		{"1.5", "1.5", true, true},
		{"1.6", "1.5", false, true},
		{"1.5.3", "==1.5.*", true, true},
		{"1.5.3", "~=1.5.0", true, true},
		{"1.6.0", "~=1.5.0", false, true},

		// Every clause between commas, as a lock and a requirement write
		// them, with or without spaces and parentheses.
		{"2.5", ">=2,<3", true, true},
		{"3.0", ">=2, <3", false, true},
		{"2.5", "(>=2,<3)", true, true},
		{"3.0.1", ">=2.7, !=3.0.*", false, true},

		// Any alternative between bars.
		{"3.5", ">=1,<2 || >=3", true, true},
		{"2.5", ">=1,<2 || >=3", false, true},

		// The Python versions an entry supports read the same way.
		{"3.12.0", ">=3.9", true, true},
		{"3.8.0", ">=3.9", false, true},

		// What cannot be read says nothing.
		{"1.5", "^1.2", false, false},
		{"not a version", ">=2", false, false},
	} {
		holds, known := satisfies(tc.version, tc.constraint)
		require.Equal(t, tc.known, known, "%s against %q: known", tc.version, tc.constraint)
		require.Equal(t, tc.holds, holds, "%s against %q: holds", tc.version, tc.constraint)
	}
}

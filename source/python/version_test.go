// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVersionOrdering walks the example ordering from the PEP 440 spec
// itself: each version must sort strictly before the next.
func TestVersionOrdering(t *testing.T) {
	t.Parallel()

	ordered := []string{
		"1.0.dev456",
		"1.0a1",
		"1.0a2.dev456",
		"1.0a12.dev456",
		"1.0a12",
		"1.0b1.dev456",
		"1.0b2",
		"1.0b2.post345.dev456",
		"1.0b2.post345",
		"1.0rc1.dev456",
		"1.0rc1",
		"1.0",
		"1.0+abc.5",
		"1.0+abc.7",
		"1.0+5",
		"1.0.post456.dev34",
		"1.0.post456",
		"1.1.dev1",
	}

	for i := range ordered[:len(ordered)-1] {
		a, err := ParseVersion(ordered[i])
		require.NoError(t, err)
		b, err := ParseVersion(ordered[i+1])
		require.NoError(t, err)
		require.Equal(t, -1, a.Compare(b), "%s should sort before %s", ordered[i], ordered[i+1])
		require.Equal(t, 1, b.Compare(a), "%s should sort after %s", ordered[i+1], ordered[i])
		require.Equal(t, 0, a.Compare(a), "%s should equal itself", ordered[i]) //nolint:gocritic // comparing a version to itself is the point
	}
}

// TestVersionEquality covers the spellings PEP 440 declares equivalent.
func TestVersionEquality(t *testing.T) {
	t.Parallel()

	for name, pair := range map[string][2]string{
		"trailing zeros are insignificant": {"1.0", "1.0.0"},
		"the v prefix is dropped":          {"v1.0", "1.0"},
		"case does not matter":             {"1.0RC1", "1.0rc1"},
		"c is an alias of rc":              {"1.0c1", "1.0rc1"},
		"alpha is an alias of a":           {"1.0alpha2", "1.0a2"},
		"separators are interchangeable":   {"1.0-rc-1", "1.0.rc.1"},
		"a bare phase is its zero":         {"1.0a", "1.0a0"},
		"post spelled as a dash":           {"1.0-1", "1.0.post1"},
		"rev is an alias of post":          {"1.0.rev4", "1.0.post4"},
		"leading zeros in segments":        {"01.01.4", "1.1.4"},
		"whitespace is trimmed":            {" 1.0 ", "1.0"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := ParseVersion(pair[0])
			require.NoError(t, err)
			b, err := ParseVersion(pair[1])
			require.NoError(t, err)
			require.Equal(t, 0, a.Compare(b), "%s and %s should be the same version", pair[0], pair[1])
		})
	}
}

func TestVersionEpoch(t *testing.T) {
	t.Parallel()

	// An epoch outranks any release: 2!1.0 sorts after 1000.
	small, err := ParseVersion("1000")
	require.NoError(t, err)
	epoched, err := ParseVersion("2!1.0")
	require.NoError(t, err)
	require.Equal(t, 1, epoched.Compare(small))
}

func TestVersionInvalid(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"", "not-a-version", "1.0.x", "1..0", "hello.1", "1.0+", "1.0++local",
	} {
		_, err := ParseVersion(s)
		require.Error(t, err, "%q should not parse", s)
	}
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoordinatePURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		coord Coordinate
		purl  string
	}{
		{"basic", Coordinate{GroupID: "com.google.guava", ArtifactID: "guava", Version: "33.0.0-jre"}, "pkg:maven/com.google.guava/guava@33.0.0-jre"},
		{"no version", Coordinate{GroupID: "g", ArtifactID: "a"}, "pkg:maven/g/a"},
		{"with type", Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0", Type: "war"}, "pkg:maven/g/a@1.0?type=war"},
		{"jar type omitted", Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0", Type: "jar"}, "pkg:maven/g/a@1.0"},
		{"with classifier", Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0", Classifier: "sources"}, "pkg:maven/g/a@1.0?classifier=sources"},
		{"with repo url", Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0", RepoURL: "https://repo.example.com/maven2"}, "pkg:maven/g/a@1.0?repository_url=https://repo.example.com/maven2"},
		{"all qualifiers", Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0", Type: "aar", Classifier: "debug", RepoURL: "https://example.com/repo"}, "pkg:maven/g/a@1.0?type=aar&classifier=debug&repository_url=https://example.com/repo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.purl, tc.coord.PURL())
		})
	}
}

func TestCoordinateString(t *testing.T) {
	t.Parallel()
	c := Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0"}
	require.Equal(t, "g:a:1.0", c.String())
}

func TestCoordinateKey(t *testing.T) {
	t.Parallel()
	c := Coordinate{GroupID: "g", ArtifactID: "a", Version: "1.0"}
	require.Equal(t, "g:a", c.Key())
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		a, b string
		want int
	}{
		// Basic numeric
		{"equal", "1.0.0", "1.0.0", 0},
		{"major", "2.0.0", "1.0.0", 1},
		{"minor", "1.1.0", "1.0.0", 1},
		{"patch", "1.0.1", "1.0.0", 1},
		{"reverse", "1.0.0", "2.0.0", -1},

		// Different segment counts
		{"short vs long equal", "1.0", "1.0.0", 0},
		{"short vs long less", "1.0", "1.0.1", -1},

		// Qualifiers
		{"alpha < beta", "1.0-alpha", "1.0-beta", -1},
		{"beta < rc", "1.0-beta", "1.0-rc", -1},
		{"rc < release", "1.0-rc1", "1.0", -1},
		{"snapshot < release", "1.0-SNAPSHOT", "1.0", -1},
		{"release < sp", "1.0", "1.0-sp1", -1},
		{"alpha aliases", "1.0-a1", "1.0-alpha1", 0},
		{"beta aliases", "1.0-b1", "1.0-beta1", 0},
		{"final = release", "1.0-final", "1.0", 0},
		{"ga = release", "1.0-ga", "1.0", 0},

		// JRE qualifier (unknown, sorts after sp)
		{"jre qualifier", "33.0.0-android", "33.0.0-jre", -1}, // both unknown, lexical

		// Mixed
		{"1.0-alpha vs 1.0.0", "1.0-alpha", "1.0.0", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CompareVersions(tc.a, tc.b)
			require.Equal(t, tc.want, got, "CompareVersions(%q, %q)", tc.a, tc.b)
		})
	}
}

func TestIsVersionRange(t *testing.T) {
	t.Parallel()
	require.True(t, IsVersionRange("[1.0,2.0)"))
	require.True(t, IsVersionRange("(,1.0]"))
	require.True(t, IsVersionRange("[1.0]"))
	require.False(t, IsVersionRange("1.0.0"))
	require.False(t, IsVersionRange(""))
}

func TestParseVersionRange(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		lower   string
		upper   string
		lowerIn bool
		upperIn bool
		mustErr bool
	}{
		{"inclusive range", "[1.0,2.0]", "1.0", "2.0", true, true, false},
		{"half open", "[1.0,2.0)", "1.0", "2.0", true, false, false},
		{"open lower", "(1.0,2.0]", "1.0", "2.0", false, true, false},
		{"exact", "[1.0]", "1.0", "1.0", true, true, false},
		{"unbounded upper", "[1.0,)", "1.0", "", true, false, false},
		{"unbounded lower", "(,2.0)", "", "2.0", false, false, false},
		{"invalid", "x", "", "", false, false, true},
		{"too short", "[", "", "", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vr, err := ParseVersionRange(tc.input)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.lower, vr.LowerBound)
			require.Equal(t, tc.upper, vr.UpperBound)
			require.Equal(t, tc.lowerIn, vr.LowerInclusive)
			require.Equal(t, tc.upperIn, vr.UpperInclusive)
		})
	}
}

func TestVersionRangeContains(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		rangeS  string
		version string
		want    bool
	}{
		{"in range", "[1.0,2.0)", "1.5", true},
		{"at lower inclusive", "[1.0,2.0)", "1.0", true},
		{"at upper exclusive", "[1.0,2.0)", "2.0", false},
		{"at upper inclusive", "[1.0,2.0]", "2.0", true},
		{"below range", "[1.0,2.0)", "0.9", false},
		{"above range", "[1.0,2.0)", "2.1", false},
		{"exact match", "[1.5]", "1.5", true},
		{"exact no match", "[1.5]", "1.6", false},
		{"unbounded upper", "[1.0,)", "99.0", true},
		{"unbounded lower", "(,2.0)", "1.0", true},
		{"unbounded lower at bound", "(,2.0)", "2.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vr, err := ParseVersionRange(tc.rangeS)
			require.NoError(t, err)
			require.Equal(t, tc.want, vr.Contains(tc.version))
		})
	}
}

func TestVersionRangeSelectVersion(t *testing.T) {
	t.Parallel()
	vr, err := ParseVersionRange("[1.0,2.0)")
	require.NoError(t, err)

	candidates := []string{"0.9", "1.0", "1.5", "1.9", "2.0", "2.1"}
	require.Equal(t, "1.9", vr.SelectVersion(candidates))

	// No candidates match
	require.Empty(t, vr.SelectVersion([]string{"0.5", "2.0", "3.0"}))
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAgainstPythonOracle replays version orderings and marker evaluations
// answered by Python's packaging library, the reference implementation of
// PEP 440 and PEP 508. The corpus is checked in, so this holds the Go
// implementation to what Python actually does without needing a Python at
// test time. Regenerate it with hack/update-python-oracle.py.
func TestAgainstPythonOracle(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/pep-oracle.json")
	require.NoError(t, err)

	var oracle struct {
		Versions []struct {
			A   string `json:"a"`
			B   string `json:"b"`
			Cmp int    `json:"cmp"`
		} `json:"versions"`
		Markers []struct {
			Marker string `json:"marker"`
			Env    string `json:"env"`
			Holds  bool   `json:"holds"`
		} `json:"markers"`
	}
	require.NoError(t, json.Unmarshal(data, &oracle))
	require.NotEmpty(t, oracle.Versions)
	require.NotEmpty(t, oracle.Markers)

	// The same environments the generator answers for.
	envs := map[string]*Environment{}
	for name, spec := range map[string][3]string{
		"linux312": {"linux", "amd64", "3.12"},
		"mac310":   {"darwin", "arm64", "3.10.2"},
		"win311":   {"windows", "amd64", "3.11.9"},
	} {
		env, err := NewEnvironment(spec[0], spec[1], spec[2])
		require.NoError(t, err)
		envs[name] = env
	}

	for _, tc := range oracle.Versions {
		a, err := ParseVersion(tc.A)
		require.NoError(t, err, "the oracle parses %q", tc.A)
		b, err := ParseVersion(tc.B)
		require.NoError(t, err, "the oracle parses %q", tc.B)
		require.Equal(t, tc.Cmp, a.Compare(b),
			"compare(%q, %q) disagrees with Python", tc.A, tc.B)
	}

	for _, tc := range oracle.Markers {
		holds, err := envs[tc.Env].Evaluate(tc.Marker)
		require.NoError(t, err, "the oracle evaluates %q", tc.Marker)
		require.Equal(t, tc.Holds, holds,
			"%q in %s disagrees with Python", tc.Marker, tc.Env)
	}
}

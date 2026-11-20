// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmake

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	commands, err := Parse(`# A comment
cmake_minimum_required(VERSION 3.14)
PROJECT(demo VERSION 1.2.3 LANGUAGES CXX) # trailing
#[[ a bracket comment
find_package(Hidden REQUIRED)
]]
find_package(OpenSSL 3.0
    REQUIRED COMPONENTS SSL Crypto)
set(NAMES a;b "c;d" [=[e ]] f]=])
if((A AND B) OR NOT "REQUIRED")
message(STATUS "a \"quoted\" value with ) and # in it")
endif ()
`)
	require.NoError(t, err)

	names := make([]string, 0, len(commands))
	for i := range commands {
		names = append(names, commands[i].Name)
	}
	require.Equal(t, []string{"cmake_minimum_required", "project", "find_package", "set", "if", "message", "endif"}, names)

	require.Equal(t, []string{"demo", "VERSION", "1.2.3", "LANGUAGES", "CXX"}, commands[1].Values())
	require.Equal(t, 3, commands[1].Line)

	require.Equal(t, []string{"OpenSSL", "3.0", "REQUIRED", "COMPONENTS", "SSL", "Crypto"}, commands[2].Values())
	require.Equal(t, 7, commands[2].Line)

	// An unquoted list is split, a quoted or bracketed one is one value.
	require.Equal(t, []string{"NAMES", "a", "b", "c;d", "e ]] f"}, commands[3].Values())
	require.True(t, commands[3].Args[3].Quoted)
	require.True(t, commands[3].Args[4].Quoted)

	// Parentheses nest, and a quoted keyword is a string.
	require.Equal(t, []string{"(", "A", "AND", "B", ")", "OR", "NOT", "REQUIRED"}, commands[4].Values())
	require.True(t, commands[4].Args[7].Quoted)

	require.Equal(t, []string{"STATUS", `a "quoted" value with ) and # in it`}, commands[5].Values())
	require.Empty(t, commands[6].Args)
}

// TestParseBroken checks text that is not CMake gives an error and what
// was read before it, and does not hang.
func TestParseBroken(t *testing.T) {
	t.Parallel()
	for name, src := range map[string]string{
		"not closed":        "project(demo)\nfind_package(OpenSSL",
		"no parenthesis":    "project(demo)\nfind_package OpenSSL\n",
		"not a command":     "project(demo)\n@@@\n",
		"an unclosed quote": "project(demo)\nmessage(\"never ends",
	} {
		commands, err := Parse(src)
		require.Error(t, err, name)
		require.Len(t, commands, 1, name)
	}

	commands, err := Parse("")
	require.NoError(t, err)
	require.Empty(t, commands)
}

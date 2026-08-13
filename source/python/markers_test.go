// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// testEnv builds an environment or fails the test.
func testEnv(t *testing.T, goos, goarch, pythonVersion string, extras ...string) *Environment {
	t.Helper()
	env, err := NewEnvironment(goos, goarch, pythonVersion)
	require.NoError(t, err)
	env.Extras = extras
	return env
}

// TestMarkerEval evaluates markers as they appear in real uv.lock files
// against concrete environments.
func TestMarkerEval(t *testing.T) {
	t.Parallel()

	linux312 := testEnv(t, "linux", "amd64", "3.12")
	linux310 := testEnv(t, "linux", "amd64", "3.10")
	windows := testEnv(t, "windows", "amd64", "3.12")
	macARM := testEnv(t, "darwin", "arm64", "3.12")

	for name, tc := range map[string]struct {
		marker string
		env    *Environment
		holds  bool
	}{
		// The markers the uv.lock probe corpus actually contains.
		"win32 colorama on linux":   {"sys_platform == 'win32'", linux312, false},
		"win32 colorama on windows": {"sys_platform == 'win32'", windows, true},
		"an old-python backport on 3.10": {
			"python_full_version < '3.11'", linux310, true,
		},
		"an old-python backport on 3.12": {
			"python_full_version < '3.11'", linux312, false,
		},
		"a resolution fork marker": {
			"python_full_version == '3.11.*' and sys_platform == 'linux'", linux312, false,
		},
		"the matching fork": {
			"python_full_version >= '3.12' and sys_platform == 'linux'", linux312, true,
		},

		// Versions compare as versions, not as strings: "3.12" < "3.9"
		// lexicographically, which is exactly the wrong answer.
		"version comparison is not string comparison": {
			"python_version >= '3.9'", linux312, true,
		},

		// and binds tighter than or.
		"or of an and, left arm": {
			"sys_platform == 'darwin' or sys_platform == 'linux' and platform_machine == 'x86_64'",
			macARM, true,
		},
		"or of an and, right arm": {
			"sys_platform == 'darwin' or sys_platform == 'linux' and platform_machine == 'x86_64'",
			linux312, true,
		},
		"or of an and, neither": {
			"sys_platform == 'darwin' or sys_platform == 'linux' and platform_machine == 'x86_64'",
			windows, false,
		},
		"parentheses override precedence": {
			"(sys_platform == 'darwin' or sys_platform == 'linux') and platform_machine == 'aarch64'",
			linux312, false,
		},

		// Substring containment, both ways.
		"in":     {"'x86' in platform_machine", linux312, true},
		"not in": {"'arm' not in platform_machine", linux312, true},

		// The environment carries the target's spelling of the machine.
		"a mac's arm is arm64":     {"platform_machine == 'arm64'", macARM, true},
		"windows spells it AMD64":  {"platform_machine == 'AMD64'", windows, true},
		"windows os_name is nt":    {"os_name == 'nt'", windows, true},
		"linux os_name is posix":   {"os_name == 'posix'", linux312, true},
		"implementation":           {"implementation_name == 'cpython'", linux312, true},
		"tilde on python versions": {"python_full_version ~= '3.10'", linux312, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			holds, err := tc.env.Evaluate(tc.marker)
			require.NoError(t, err)
			require.Equal(t, tc.holds, holds)
		})
	}
}

// TestMarkerExtras covers the extra variable, whose equality is membership
// in the set of enabled extras.
func TestMarkerExtras(t *testing.T) {
	t.Parallel()

	withColor := testEnv(t, "linux", "amd64", "3.12", "color")
	plain := testEnv(t, "linux", "amd64", "3.12")

	for name, tc := range map[string]struct {
		marker string
		env    *Environment
		holds  bool
	}{
		"an enabled extra":       {"extra == 'color'", withColor, true},
		"a disabled extra":       {"extra == 'color'", plain, false},
		"negation":               {"extra != 'cli'", withColor, true},
		"negation of an enabled": {"extra != 'color'", withColor, false},
		"the literal first":      {"'color' == extra", withColor, true},
		"names are normalized":   {"extra == 'Color_Extra'", testEnv(t, "linux", "amd64", "3.12", "color-extra"), true},
		"alongside a condition":  {"extra == 'color' and sys_platform == 'linux'", withColor, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			holds, err := tc.env.Evaluate(tc.marker)
			require.NoError(t, err)
			require.Equal(t, tc.holds, holds)
		})
	}
}

func TestMarkerEmpty(t *testing.T) {
	t.Parallel()

	// A dependency with no marker is unconditional.
	holds, err := testEnv(t, "linux", "amd64", "3.12").Evaluate("")
	require.NoError(t, err)
	require.True(t, holds)
}

func TestMarkerErrors(t *testing.T) {
	t.Parallel()

	env := testEnv(t, "linux", "amd64", "3.12")
	for name, marker := range map[string]string{
		"an unknown variable":    "the_weather == 'nice'",
		"an unterminated string": "sys_platform == 'linux",
		"a missing operand":      "sys_platform ==",
		"a missing operator":     "sys_platform 'linux'",
		"trailing garbage":       "sys_platform == 'linux' banana",
		"not without in":         "sys_platform not 'linux'",
		"an unclosed paren":      "(sys_platform == 'linux'",
		"an ordering on extra":   "extra >= 'color'",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := env.Evaluate(marker)
			require.Error(t, err)
		})
	}
}

// TestNewEnvironment covers the platform translation: the same GOOS/GOARCH
// pair maps to what a real interpreter on that platform reports.
func TestNewEnvironment(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		goos, goarch string
		machine      string
		sysPlatform  string
		osName       string
	}{
		"linux amd64":   {"linux", "amd64", "x86_64", "linux", "posix"},
		"linux arm64":   {"linux", "arm64", "aarch64", "linux", "posix"},
		"mac amd64":     {"darwin", "amd64", "x86_64", "darwin", "posix"},
		"mac arm64":     {"darwin", "arm64", "arm64", "darwin", "posix"},
		"macos alias":   {"macos", "arm64", "arm64", "darwin", "posix"},
		"windows amd64": {"windows", "amd64", "AMD64", "win32", "nt"},
		"windows arm64": {"windows", "arm64", "ARM64", "win32", "nt"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env, err := NewEnvironment(tc.goos, tc.goarch, "3.12")
			require.NoError(t, err)
			require.Equal(t, tc.machine, env.PlatformMachine)
			require.Equal(t, tc.sysPlatform, env.SysPlatform)
			require.Equal(t, tc.osName, env.OSName)
		})
	}

	t.Run("the host platform is the default", func(t *testing.T) {
		t.Parallel()
		env, err := NewEnvironment("", "", "3.12")
		require.NoError(t, err)
		require.NotEmpty(t, env.SysPlatform)
		require.NotEmpty(t, env.PlatformMachine)
	})

	t.Run("python versions", func(t *testing.T) {
		t.Parallel()
		env, err := NewEnvironment("linux", "amd64", "3.12")
		require.NoError(t, err)
		require.Equal(t, "3.12", env.PythonVersion)
		require.Equal(t, "3.12.0", env.PythonFullVersion)

		env, err = NewEnvironment("linux", "amd64", "3.12.4")
		require.NoError(t, err)
		require.Equal(t, "3.12", env.PythonVersion)
		require.Equal(t, "3.12.4", env.PythonFullVersion)
	})

	t.Run("rejections", func(t *testing.T) {
		t.Parallel()
		for name, args := range map[string][3]string{
			"an unknown os":           {"plan9", "amd64", "3.12"},
			"an unknown arch":         {"linux", "mips", "3.12"},
			"a mac does not do s390x": {"darwin", "s390x", "3.12"},
			"a bare major version":    {"linux", "amd64", "3"},
			"not a version":           {"linux", "amd64", "latest"},
			"a local version":         {"linux", "amd64", "3.12+local"},
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				_, err := NewEnvironment(args[0], args[1], args[2])
				require.Error(t, err)
			})
		}
	})
}

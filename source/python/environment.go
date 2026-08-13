// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"runtime"
	"strings"
)

// Environment is the concrete target environment markers evaluate against:
// one operating system, one architecture, one Python version, one set of
// enabled extras. A lockfile resolves for every environment at once; an
// extraction is for one of these.
type Environment struct {
	// The PEP 508 environment variables, named as the markers name them.
	OSName                       string // os_name: "posix", "nt"
	SysPlatform                  string // sys_platform: "linux", "darwin", "win32"
	PlatformSystem               string // platform_system: "Linux", "Darwin", "Windows"
	PlatformMachine              string // platform_machine: "x86_64", "aarch64", "arm64", "AMD64"
	PythonVersion                string // python_version: "3.12"
	PythonFullVersion            string // python_full_version: "3.12.0"
	ImplementationName           string // implementation_name: "cpython"
	PlatformPythonImplementation string // platform_python_implementation: "CPython"

	// Extras are the enabled extras, normalized. The "extra" marker
	// variable evaluates against this set.
	Extras []string
}

// NewEnvironment builds the environment for an operating system and
// architecture in Go's vocabulary (GOOS and GOARCH names), and a Python
// version stated as "3.12" or "3.12.4". Empty os or arch mean the platform
// unpack itself runs on.
//
// The translation is the reason this constructor exists: Python spells the
// same platform several ways, and the values must agree with what real
// interpreters report — linux/arm64 is aarch64, but a Mac's arm64 stays
// arm64 and Windows spells it ARM64.
func NewEnvironment(goos, goarch, pythonVersion string) (*Environment, error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	env := &Environment{
		ImplementationName:           "cpython",
		PlatformPythonImplementation: "CPython",
	}

	switch goos {
	case platformLinux:
		env.OSName, env.SysPlatform, env.PlatformSystem = "posix", platformLinux, "Linux"
	case platformDarwin, "macos":
		env.OSName, env.SysPlatform, env.PlatformSystem = "posix", platformDarwin, "Darwin"
	case "windows":
		env.OSName, env.SysPlatform, env.PlatformSystem = "nt", platformWin32, "Windows"
	default:
		return nil, fmt.Errorf("unknown operating system %q", goos)
	}

	machine, err := machineName(env.SysPlatform, goarch)
	if err != nil {
		return nil, err
	}
	env.PlatformMachine = machine

	if err := env.setPythonVersion(pythonVersion); err != nil {
		return nil, err
	}
	return env, nil
}

// machines translates GOARCH names to what each target's interpreter
// reports as platform_machine, which differs by operating system: linux
// arm64 is aarch64, a Mac's stays arm64, and Windows shouts AMD64.
// The platform names shared between the os switch and the machine table.
const (
	platformLinux  = "linux"
	platformDarwin = "darwin"
	platformWin32  = "win32"
	archAmd64      = "amd64"
	archArm64      = "arm64"
)

var machines = map[string]map[string]string{
	platformLinux: {
		archAmd64: "x86_64", archArm64: "aarch64", "386": "i686", "arm": "armv7l",
		"ppc64le": "ppc64le", "s390x": "s390x", "riscv64": "riscv64",
	},
	platformDarwin: {archAmd64: "x86_64", archArm64: "arm64"},
	platformWin32:  {archAmd64: "AMD64", archArm64: "ARM64", "386": "x86"},
}

// machineName translates a GOARCH name to the target's platform_machine.
func machineName(sysPlatform, goarch string) (string, error) {
	machine, ok := machines[sysPlatform][goarch]
	if !ok {
		return "", fmt.Errorf("unknown architecture %q for %s", goarch, sysPlatform)
	}
	return machine, nil
}

// setPythonVersion fills the two version variables from one stated version:
// python_version is always major.minor, python_full_version the full
// version, with a .0 patch assumed when only major.minor is given.
func (env *Environment) setPythonVersion(version string) error {
	parsed, err := ParseVersion(version)
	if err != nil || len(parsed.Release) < 2 || parsed.Local != "" {
		return fmt.Errorf("%q is not a Python version to target (want major.minor or fuller)", version)
	}
	env.PythonVersion = fmt.Sprintf("%d.%d", parsed.Release[0], parsed.Release[1])
	if len(parsed.Release) == 2 && !parsed.HasPre && !parsed.HasDev && !parsed.HasPost {
		env.PythonFullVersion = env.PythonVersion + ".0"
		return nil
	}
	env.PythonFullVersion = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
	return nil
}

// lookup resolves a marker variable to its value in this environment.
func (env *Environment) lookup(name string) (string, error) {
	switch name {
	case "os_name":
		return env.OSName, nil
	case "sys_platform":
		return env.SysPlatform, nil
	case "platform_system":
		return env.PlatformSystem, nil
	case "platform_machine":
		return env.PlatformMachine, nil
	case "python_version":
		return env.PythonVersion, nil
	case "python_full_version":
		return env.PythonFullVersion, nil
	case "implementation_name":
		return env.ImplementationName, nil
	case "platform_python_implementation":
		return env.PlatformPythonImplementation, nil
	case "implementation_version":
		return env.PythonFullVersion, nil
	case "platform_release", "platform_version":
		// Kernel release and build strings: real values exist only on a
		// running system. Markers on them are rare and vendor-specific;
		// comparing against empty keeps evaluation total.
		return "", nil
	default:
		return "", fmt.Errorf("unknown marker variable %q", name)
	}
}

// hasExtra says whether an extra is enabled, comparing normalized names.
func (env *Environment) hasExtra(name string) bool {
	for _, extra := range env.Extras {
		if NormalizeName(extra) == name {
			return true
		}
	}
	return false
}

// Evaluate parses and evaluates a marker in this environment. An empty
// marker holds everywhere: a dependency with no marker is unconditional.
func (env *Environment) Evaluate(marker string) (bool, error) {
	if strings.TrimSpace(marker) == "" {
		return true, nil
	}
	m, err := ParseMarker(marker)
	if err != nil {
		return false, err
	}
	return m.Eval(env)
}

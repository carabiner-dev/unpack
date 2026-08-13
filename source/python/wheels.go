// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"fmt"
	"path"
	"strings"
)

// This file picks the distribution artifact a target environment would
// install, which is what a node's hash has to be: PyPI attestations bind to
// individual files, so an SBOM hash is only verifiable if it names the file
// the environment actually gets. The choice mirrors an installer's: the most
// specific compatible wheel, a universal wheel after that, and the sdist
// when no wheel fits.

// selectArtifact returns the artifact env would install from pkg, or nil
// when the package has none at all (a project's own packages carry none).
func selectArtifact(pkg *Package, env *Environment) *Artifact {
	best := (*Artifact)(nil)
	bestScore := -1
	for i := range pkg.Wheels {
		wheel := &pkg.Wheels[i]
		score, ok := wheelScore(wheel.URL, env)
		if ok && score > bestScore {
			best, bestScore = wheel, score
		}
	}
	if best != nil {
		return best
	}
	return pkg.Sdist
}

// wheelScore says whether the wheel a URL names installs on env, and how
// specifically it targets it: a platform wheel built for this exact
// interpreter outranks an abi3 one, which outranks a pure-Python universal
// wheel. The ranking mirrors installer preference so the artifact chosen is
// the one an install would fetch.
func wheelScore(url string, env *Environment) (score int, ok bool) {
	python, abi, platform, err := wheelTags(path.Base(url))
	if err != nil {
		return 0, false
	}

	pythonOK, exact := pythonTagOK(python, abi, env)
	if !pythonOK || !platformTagOK(platform, env) {
		return 0, false
	}

	score = 0
	if !hasTag(platform, "any") {
		score += 2
	}
	if exact {
		score++
	}
	return score, true
}

// wheelTags takes the three compatibility tags off a wheel filename:
// name-version(-build)?-python-abi-platform.whl. Each tag position may hold
// several dot-joined alternatives.
func wheelTags(filename string) (python, abi, platform string, err error) {
	stem, isWheel := strings.CutSuffix(filename, ".whl")
	if !isWheel {
		return "", "", "", fmt.Errorf("%q is not a wheel", filename)
	}
	parts := strings.Split(stem, "-")
	if len(parts) < 5 {
		return "", "", "", fmt.Errorf("%q is not a wheel filename", filename)
	}
	return parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1], nil
}

// hasTag says whether one of a position's dot-joined alternatives is tag.
func hasTag(position, tag string) bool {
	for _, alternative := range strings.Split(position, ".") {
		if alternative == tag {
			return true
		}
	}
	return false
}

// pythonTagOK says whether the interpreter tags fit env's CPython, and
// whether they name it exactly. A pure-Python tag (py3) fits any version; a
// CPython tag (cp312) fits its own, or any newer one when the wheel is
// stable-ABI (abi3).
func pythonTagOK(python, abi string, env *Environment) (fits, exact bool) {
	target := "cp" + strings.ReplaceAll(env.PythonVersion, ".", "")
	for _, tag := range strings.Split(python, ".") {
		switch {
		case tag == target:
			return true, true
		case tag == "py3" || tag == "py2.py3" || tag == "py"+strings.ReplaceAll(env.PythonVersion, ".", ""):
			return true, false
		case hasTag(abi, "abi3") && strings.HasPrefix(tag, "cp"):
			// A stable-ABI wheel built for an older CPython runs on newer
			// ones: cp38-abi3 installs on 3.12.
			if wheelVersionAtMost(tag, target) {
				return true, false
			}
		}
	}
	return false, false
}

// wheelVersionAtMost says whether the cpXY tag names a version at or below
// the cpXY target. Both encode major and minor with no separator, so 310 is
// 3.10 and the comparison peels the major digit off.
func wheelVersionAtMost(tag, target string) bool {
	if len(tag) < 4 || len(target) < 4 {
		return false
	}
	tagV, err1 := ParseVersion(tag[2:3] + "." + tag[3:])
	targetV, err2 := ParseVersion(target[2:3] + "." + target[3:])
	if err1 != nil || err2 != nil {
		return false
	}
	return tagV.Compare(targetV) <= 0
}

// platformTagOK says whether one of the platform tags installs on env.
//
// Linux wheels are matched on the glibc (manylinux) family: a musllinux
// wheel is for Alpine-style systems, which the environment model does not
// distinguish, so glibc is assumed. macOS universal2 fits both Mac
// architectures.
func platformTagOK(platform string, env *Environment) bool {
	for _, tag := range strings.Split(platform, ".") {
		if tag == "any" || platformTagFits(tag, env) {
			return true
		}
	}
	return false
}

func platformTagFits(tag string, env *Environment) bool {
	switch env.SysPlatform {
	case platformLinux:
		return (strings.HasPrefix(tag, "manylinux") || strings.HasPrefix(tag, "linux")) &&
			strings.HasSuffix(tag, "_"+env.PlatformMachine)
	case platformDarwin:
		return strings.HasPrefix(tag, "macosx_") &&
			(strings.HasSuffix(tag, "_"+env.PlatformMachine) || strings.HasSuffix(tag, "_universal2"))
	case platformWin32:
		switch env.PlatformMachine {
		case "AMD64":
			return tag == "win_amd64"
		case "ARM64":
			return tag == "win_arm64"
		default:
			return tag == platformWin32
		}
	default:
		return false
	}
}

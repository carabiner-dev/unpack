#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates source/python/testdata/pep-oracle.json: version orderings and
# marker evaluations answered by Python's own packaging library, which is the
# reference implementation of PEP 440 and PEP 508. The Go tests replay these
# answers, so the Go implementation is held to what Python actually does
# rather than to what we believe the specs say.
#
#   python3 hack/update-python-oracle.py > source/python/testdata/pep-oracle.json
#
# Requires the packaging distribution (pip install packaging).

import itertools
import json

from packaging.markers import Marker
from packaging.version import Version

VERSIONS = [
    "1.0", "1.0.0", "1.1", "0.9", "2!0.1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1",
    "1.0.dev3", "1.0a1.dev1", "1.0.post1", "1.0.post1.dev2", "1.0+local", "1.0+abc.5",
    "1.0+5", "1.0+abc", "3.9", "3.10", "3.11.4", "3.12", "2.28.1", "1!1.0",
    "0.0.1", "1.0rc1.post1", "1.0-1", "v2.0", "2.0.0.0.1",
]

# The environments mirror what unpack's NewEnvironment builds for
# (linux, amd64, 3.12), (darwin, arm64, 3.10.2) and (windows, amd64, 3.11.9).
ENVS = {
    "linux312": {
        "os_name": "posix", "sys_platform": "linux", "platform_system": "Linux",
        "platform_machine": "x86_64", "python_version": "3.12",
        "python_full_version": "3.12.0", "implementation_name": "cpython",
        "platform_python_implementation": "CPython", "platform_release": "",
        "platform_version": "", "implementation_version": "3.12.0",
    },
    "mac310": {
        "os_name": "posix", "sys_platform": "darwin", "platform_system": "Darwin",
        "platform_machine": "arm64", "python_version": "3.10",
        "python_full_version": "3.10.2", "implementation_name": "cpython",
        "platform_python_implementation": "CPython", "platform_release": "",
        "platform_version": "", "implementation_version": "3.10.2",
    },
    "win311": {
        "os_name": "nt", "sys_platform": "win32", "platform_system": "Windows",
        "platform_machine": "AMD64", "python_version": "3.11",
        "python_full_version": "3.11.9", "implementation_name": "cpython",
        "platform_python_implementation": "CPython", "platform_release": "",
        "platform_version": "", "implementation_version": "3.11.9",
    },
}

MARKERS = [
    "python_full_version < '3.11'",
    "python_full_version >= '3.12' and sys_platform == 'linux'",
    "python_full_version == '3.11.*'",
    "python_full_version != '3.11.*'",
    "python_version ~= '3.10'",
    "python_full_version ~= '3.10.1'",
    "sys_platform == 'darwin' or sys_platform == 'linux' and platform_machine == 'x86_64'",
    "(sys_platform == 'darwin' or sys_platform == 'linux') and platform_machine == 'arm64'",
    "'x86' in platform_machine",
    "'arm' not in platform_machine",
    "python_version >= '3.9'",
    "python_version <= '3.10'",
    "os_name == 'nt' or python_full_version < '3.11.5'",
    "platform_machine == 'AMD64' and python_version == '3.11'",
    "python_version in '3.10 3.11'",
    "python_full_version > '3.10.1'",
    "implementation_name == 'cpython' and platform_python_implementation == 'CPython'",
    "sys_platform != 'win32' or python_version != '3.11'",
]


def main() -> None:
    pairs = []
    for a, b in itertools.product(VERSIONS, VERSIONS):
        va, vb = Version(a), Version(b)
        pairs.append({"a": a, "b": b, "cmp": -1 if va < vb else (0 if va == vb else 1)})

    mcases = []
    for text in MARKERS:
        marker = Marker(text)
        for name, env in ENVS.items():
            mcases.append({"marker": text, "env": name, "holds": marker.evaluate(env)})

    print(json.dumps({"versions": pairs, "markers": mcases}, indent=1))


if __name__ == "__main__":
    main()

# Unpack: The Dependency-Aware File Unpacker

[![Go Build and Test](https://github.com/carabiner-dev/unpack/actions/workflows/go-build-and-test.yaml/badge.svg)](https://github.com/carabiner-dev/unpack/actions/workflows/go-build-and-test.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/carabiner-dev/unpack)](https://goreportcard.com/report/github.com/carabiner-dev/unpack)
[![LICENSE](https://img.shields.io/github/license/carabiner-dev/unpack)](./LICENSE)

**Unpack** is a versatile CLI tool and library for analyzing software components. It goes beyond simple file extraction, providing deep insights into dependencies within codebases, artifacts, and Software Bills of Materials (SBOMs).

Whether you're a developer, security researcher, or compliance officer, Unpack helps you understand the composition of your software.

## Key Features

- **Dependency Extraction**: Analyzes source code to discover dependencies for various languages.
- **SBOM Parsing**: Reads and understands major SBOM formats: SPDX 2.2, 2.3 and 3.0.1, and CycloneDX.
- **Multiple Output Formats**: Displays dependencies as a visual tree or exports to standard SBOM formats.
- **Extensible Architecture**: Easily extendable to support new languages and package managers.
- **Attestation Support**: Wraps SBOM outputs in an in-toto attestation for verifiable supply chain security.

---

:warning: `unpack` is an experimental project. We are actively developing it and welcome feedback. Support currently covers Go, Rust, npm, Maven and Python (uv) codebases, with more on the way. Dependency extraction from SBOMs is powered by the native [protobom unserializers](http://github.com/protobom/protobom/).

---

## Installation

### From Pre-releases
Pre-release binaries are available for Linux, macOS, and Windows.

[**Download the latest prerelease**](https://github.com/carabiner-dev/unpack/releases/latest)

### From Source
To install the latest development version directly from the source, use the Go compiler:

```bash
go install github.com/carabiner-dev/unpack@main
```

## Usage

Unpack provides two main commands: `extract` and `sbom`.

### `unpack extract`: Analyze Source Code

Use `extract` to discover dependencies directly from a source code repository.

**Example: Basic Tree View**
```bash
# Analyze the codebase in the current directory and display a dependency tree
unpack extract .
```
```
pkg:golang/github.com/carabiner-dev/unpack@v0.1.0-pre3.1+0400cac1
  ├ pkg:golang/github.com/titanous/rocacheck@v0.0.0-20171023193734-afe73141d399
  ├ pkg:golang/google.golang.org/protobuf@v1.36.5
  │   ├ pkg:golang/github.com/google/go-cmp@v0.5.5
  ...
```

**Example: Generate an SPDX SBOM**
```bash
# Output the dependency graph as an SPDX 2.3 JSON file
unpack extract --format=spdx /path/to/your/code > my-project.spdx.json

# ...or as SPDX 3.0.1
unpack extract --format=spdx3 /path/to/your/code > my-project.spdx3.json
```

The output formats are:

| `--format` | Writes |
|---|---|
| `tree` | an ASCII dependency tree (the default) |
| `spdx` | SPDX 2.3, JSON |
| `spdx3` | SPDX 3.0.1, JSON-LD |
| `cyclonedx`, `cdx` | CycloneDX 1.7, JSON |

**Example: Target a Platform**

Some ecosystems resolve different dependencies for different platforms.
Python is one: a `uv.lock` holds the resolution for every environment the
project supports, and the extraction reads it for one.

```bash
# What does this project install on an ARM Linux box running Python 3.10?
unpack extract --platform linux/arm64 --python-version 3.10 /path/to/your/code
```

By default unpack resolves for the platform it runs on, and for Python,
the newest interpreter version the lockfile supports.

**Example: Create a Signed Attestation**
```bash
# Generate an SBOM and wrap it in a signed in-toto attestation.
# Attesting without naming a format writes SPDX 3.0.1.
unpack extract --attest /path/to/your/code

# ...or name the format yourself
unpack extract --attest --format=spdx /path/to/your/code
```

Attestations are made under the predicate type of what they carry:
`https://spdx.dev/Document/v3` for SPDX 3, `https://spdx.dev/Document` for
SPDX 2, and `https://cyclonedx.org/bom` for CycloneDX.

### `unpack sbom`: Process Existing SBOMs

Use `sbom` to read, convert, and re-export existing SBOM files.

```bash
# Read an SBOM and display its contents as a tree
unpack sbom -p /path/to/sbom.spdx.json

# Convert an SBOM to CycloneDX
unpack sbom -p /path/to/sbom.spdx.json --format=cyclonedx

# Convert an SPDX 2.3 SBOM to SPDX 3.0.1
unpack sbom -p /path/to/sbom.spdx.json --format=spdx3
```

### `unpack ls`: List Discovered Codebases

Use `ls` to scan a directory and list the codebases found, along with their IDs. These IDs can then be used with the `extract` command.

**Example: List codebases in a directory (table format)**
```bash
# List all discovered codebases in the current directory
unpack ls .
```
```
ID                     LANGUAGE   PATH
golang:.               golang     .
npm:frontend           npm        frontend
rust:backend/api       rust       backend/api
```

**Example: List codebases in JSON format**
```bash
unpack ls --format=json /path/to/project
```

**Example: List codebases ignoring specific patterns**
```bash
unpack ls --ignore "*/testdata/*" --ignore "temp/" .
```

## Supported Ecosystems

Unpack includes decomposers for five package ecosystems. See the
[decomposer documentation](docs/decomposers/README.md) for details.
Container image scans additionally report installed Python environments
(site-packages) next to the OS package inventory.

| Ecosystem | Lock file | Manifest | Remote enrichment |
| --- | --- | --- | --- |
| [Go](docs/decomposers/golang.md) | `go.sum` | `go.mod` | Go module proxy |
| [Maven](docs/decomposers/maven.md) | _(none)_ | `pom.xml` | Maven Central |
| [npm](docs/decomposers/npm.md) | `package-lock.json` | `package.json` | _(none)_ |
| [Python](docs/decomposers/python.md) | `uv.lock`, `poetry.lock`, `requirements.txt` | `pyproject.toml` (poetry) | PyPI JSON API |
| [Rust](docs/decomposers/rust.md) | `Cargo.lock` | `Cargo.toml` | crates.io API |

Support for more ecosystems is planned.

## Contributing

We welcome contributions! Whether it's reporting a bug, suggesting a feature, or submitting a pull request, your feedback is valuable.

- **Open an Issue**: If you find a problem or have an idea for an improvement, please [open a new issue](https://github.com/carabiner-dev/unpack/issues).
- **Pull Requests**: Feel free to fork the repository and submit a pull request with your changes.

## License

This tool and its libraries are released under the Apache 2.0 License and copyright by
Carabiner Systems, Inc. See the [LICENSE](./LICENSE) file for more details. Feel free to
open issues to report problems or request features. Patches are welcome!

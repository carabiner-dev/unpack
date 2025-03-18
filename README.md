# unpack: Your Handy Dependency Extractor

A collection of dependency analysis libraries and CLI tool to extract dependency 
data from codebases, artifacts and software bills of materials (SBOMs).

unpack is still an experimental project. We have initial support to extract data
from go and rust codebases (more are on the way). It has support for dependency
extraction from SBOMs via the native 
[protobom unserializers](http://github.com/protobom/protobom/).

## Install

As `unpack` is still in a prerelease state, we have not released binary artifacts.
For now use go install or clone the repo and build:

```bash
go install github.com/carabiner-dev/unpack@latest
```

## Usage

### Extract Source Dependency Data

To extract dependency data from code bases use `unpack extract`:

```bash
# Extract the dependency data of a code base im a tree: 
unpack extract /path/to/code

# Same but output in an SPDX SBOM:
unpack extract --format=spdx /path/to/code 

# Same SPDX document, but wrapped in an intoto attestation
unpack extract --attest --format=spdx /path/to/code 
```

### Extract SBOM Dependency Data

To extract data from an SBOM, use `unpack sbom`:

```bash
# Extract the dependency data from an SBOM:
unpack sbom /path/to/sbom.spdx.json

# Same but output the SBOM data in another format:
unpack sbom --format=cyclonedx /path/to/sbom.spdx.json 
```

## Patches Welcome!

This tool and its libraries are released under the Apache 2.0 license by
Carbiner Systems, Inc. Feel free to contribute improvements or report any
problems you find by opening a new issue. We love feedback and love to make
the project useful for you.

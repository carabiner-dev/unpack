# unpack: Your Handy Dependency Extractor

A collection of dependency analysis libraries and CLI tool to extract dependency 
data from codebases, artifacts and software bills of materials (SBOMs).

The project can output the dependency data to the native SBOM formats as well as
visualize them on screen:

```
> unpack extract . 

pkg:golang/github.com/carabiner-dev/unpack@v0.1.0-pre3.1+0400cac1
  ├ pkg:golang/github.com/titanous/rocacheck@v0.0.0-20171023193734-afe73141d399
  ├ pkg:golang/google.golang.org/protobuf@v1.36.5
  │   ├ pkg:golang/github.com/google/go-cmp@v0.5.5
  │   ├ pkg:golang/golang.org/x/xerrors@v0.0.0-20191204190536-9bdfabe68543
  │   ├ pkg:golang/go@1.21
  │   └ pkg:golang/github.com/golang/protobuf@v1.5.0
  ├ pkg:golang/github.com/cloudflare/circl@v1.6.0
  │   ├ pkg:golang/github.com/bwesterb/go-ristretto@v1.2.3
  │   ├ pkg:golang/golang.org/x/crypto@v0.11.1-0.20230711161743-2e82bdd1719d
  │   ├ pkg:golang/golang.org/x/sys@v0.10.0
  │   └ pkg:golang/go@1.22.0
  ├ pkg:golang/github.com/skeema/knownhosts@v1.3.1
  │   ├ pkg:golang/golang.org/x/crypto@v0.32.0
  │   ├ pkg:golang/golang.org/x/sys@v0.29.0
  │   └ pkg:golang/go@1.22
  ...
```

:warning: `unpack` is still an experimental project. We have initial support to extract data
from go and rust codebases (more are on the way). It has support for dependency
extraction from SBOMs via the native 
[protobom unserializers](http://github.com/protobom/protobom/).

## Install

We have started building binaries for the project, but we only have prereleases
at the moment. Feel free to try them out, 
[downlad the latest prerelease](https://github.com/carabiner-dev/unpack/releases/latest).

If you want to try the latest and greatest, (am possibly the buggiest! :upside_down_face: )
install directly with the go compiler:

```bash
go install github.com/carabiner-dev/unpack@HEAD
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

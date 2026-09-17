# Go Binary Decomposer

**Location:** `artifact/gobinary/`

Reads the dependency data the Go toolchain embeds in every executable it
links with module support: the main module, the exact set of modules
built into the binary with their versions and `h1:` checksums, the Go
release, and the build settings. Nothing but the file is needed: no
source tree, no `go.mod`, no `go` command. It is the first decomposer of
the **artifact** unpacker, which probes files for artifacts that carry
their own dependency data, and it runs wherever that unpacker runs: on a
file or directory handed to `unpack artifact`, and inside every container
image `unpack image` scans.

## How it works

1. **Cheap filter.** Only files whose first bytes carry an ELF, PE or
   Mach-O magic number are read further. The exec bit and the file name
   are ignored: a Go program in an image rarely has a telling name.
2. **Probe.** `debug/buildinfo` parses the object headers and reads the
   build information record. Executables that are not Go programs, or
   were built without modules, fail this step and are disowned without
   an error. That is the common case in an image and is deliberately
   silent.
3. **Module set.** The build information is reduced to the same
   `ModuleSet` the [Go source decomposer](golang.md) builds from `go.mod`
   and `go.sum`: the main module, the Go release, and every linked module
   with its checksum. A module replaced by another module enters as the
   replacement, which is what was linked; a module replaced by a local
   directory keeps its original identity, as the source decomposer does.
4. **Graph.** The set is rendered by the Go source decomposer's graph
   builder. Edges among the linked modules come from each module's own
   `go.mod`, read from the local module cache and, when networking
   allows, the module proxy, and are kept only when both ends were
   linked. License and repository enrichment runs as for source.
5. **Root.** The artifact unpacker wraps the result under a file node
   carrying the path and SHA-256 of the executable, related to the main
   module with a `generatedFrom` edge. The parent that found the file
   decides how the file relates to it: an image `contains` it.

```
usr/local/bin/tool                          (file, sha256)
  └ generatedFrom ─▶ pkg:golang/example.com/app@v1.2.3   (application)
                        ├ dependsOn ─▶ pkg:golang/stdlib@1.24.0
                        ├ dependsOn ─▶ pkg:golang/github.com/spf13/cobra@v1.9.1
                        │                 └ dependsOn ─▶ pkg:golang/github.com/spf13/pflag@v1.0.6
                        └ dependsOn ─▶ ...
```

## Data produced

### The root: the main module

| Field | Source | Notes |
|-------|--------|-------|
| Name | `Main.Path` | Falls back to the main package path for binaries built outside a module |
| Version | `Main.Version` | Omitted when Go stamped `(devel)`; `DecomposerOptions.Version` overrides either way |
| PURL | computed | `pkg:golang/{module}@{version}` |
| Primary purpose | fixed | `APPLICATION` |
| VCS reference | `vcs.revision` setting | SHA-1 of the commit the binary was built from, when built with VCS stamping; `DecomposerOptions.CommitHash` overrides |
| `go:package` property | `Path` | The main package that was built (`example.com/app/cmd/app`) |
| `goos`, `goarch` properties | build settings | The target platform |

### Per dependency

The same fields the [Go source decomposer](golang.md#data-produced-per-dependency)
produces, from the same builder: name, version, purl, download URL, the
`h1:` dirhash as a SHA-256, and the license and source repository from
deps.dev when networking allows.

### Special nodes

- **stdlib** -- `pkg:golang/stdlib@{go release}`, from the `GoVersion`
  the binary records (`go1.24.0` becomes `1.24.0`; a development
  toolchain such as `devel go1.25-0123abcd` becomes `1.25-0123abcd`).

## Where it runs

The artifact unpacker asks its decomposers where they want to run by
default (the `api.SubjectDefaults` trait). This one answers **images and
system roots**: executables are the payload there. It does not answer
**codebases**, so `unpack extract` never probes binaries lying in a
source tree. A caller can always override the default:

| Context | Default | Switch off | Switch on |
|---------|---------|------------|-----------|
| `unpack artifact PATH` | runs (no parent, every decomposer runs) | `--skip-artifact gobinary` | -- |
| `unpack image REF` | runs | `--no-artifacts` or `--skip-artifact gobinary` | -- |
| `image.Unpacker` (library) | runs | `Options.SkipArtifacts`, or `Options.ArtifactDecomposers["gobinary"] = false` | `Options.ArtifactDecomposers["gobinary"] = true` |
| `artifact.Unpacker` under another parent | per `DefaultsFor(parentType)` | `Options.Decomposers["gobinary"] = false` | `Options.Decomposers["gobinary"] = true` |

## Options

The decomposer has no options of its own. `DefaultOptions` returns the
Go source decomposer's options, and driver options set for this
decomposer are forwarded to it, so `ProxyURL`, `Concurrency`,
`HTTPClient` and `PreferModuleCache` apply as documented on the
[Go page](golang.md#options). The networking level comes from the
artifact unpacker's options (`--networking` on the CLI).

## Dependency types

Build information does not say whether a module was a direct or a
transitive requirement, only that it was linked. Every linked module is a
`dependsOn` of the root; the edges among modules refine the picture when
their `go.mod` files can be read. The inclusion flags are no-ops, as for
Go source.

## Strengths

- **Ground truth.** The list is what the linker actually used, after
  every replace, exclude and minimal version selection decision. It
  cannot drift from the build the way a `go.mod` in a repository can.
- **Works on the deployed thing.** A distroless image with one Go
  binary in it reports that binary's modules next to the (empty) OS
  inventory. No source checkout, no build.
- **Checksums for free.** The `h1:` sums travel in the binary, so
  hashes are present offline.
- **Same graph as source.** A binary and its source tree render through
  one builder, so the two SBOMs can be compared node for node.

## Weaknesses

- **No direct/transitive distinction.** The root depends on every linked
  module; only the module-to-module edges, which need the module cache
  or the proxy, show the real structure.
- **Build info can be absent.** Binaries built with GOPATH mode, or with
  build information stripped by unusual tooling, are disowned. `-s -w`
  does not strip it; `-buildvcs=false` only drops the VCS settings.
- **Only whole modules.** Go records the modules linked, not the
  packages, so a module of which one small package was used counts in
  full.
- **Executables only.** Go plugins, archives (`.a`) and WebAssembly
  outputs are not probed. The magic filter stops at ELF, PE and Mach-O.

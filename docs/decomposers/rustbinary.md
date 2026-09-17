# Rust Binary Decomposer

**Location:** `artifact/rustbinary/`

Reads the dependency record that [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable)
embeds in the Rust executables it builds: every crate linked into the
binary with its version and source, which crates are build dependencies,
and the edges among them. Nothing but the file is needed. It is a
decomposer of the **artifact** unpacker and runs wherever that unpacker
runs: on a file or directory handed to `unpack artifact`, and inside
every container image `unpack image` scans.

Plain `cargo build` records nothing; the record is there only when the
binary was built with `cargo auditable build`, which Rust-focused
distributions and a growing number of projects do. A Rust executable
without it is disowned silently, like any other executable that is not
ours.

## How it works

1. **Cheap filter.** Only files whose first bytes carry an ELF, PE or
   Mach-O magic number are read further.
2. **Section.** The record lives in a linker section named `.dep-v0` (in
   the `__DATA` segment on Mach-O). The object headers are parsed with the
   standard library's `debug/elf`, `debug/pe` and `debug/macho`, and the
   section is read in place; the rest of the file is never touched. No
   section, or a file that does not parse, means not ours.
3. **Record.** The section holds zlib-compressed JSON in the
   `auditable-serde` schema: a `packages` array, each with `name`,
   `version`, `source`, an optional `kind` (`runtime` or `build`),
   `dependencies` as indices into the array, and `root` on the crate the
   binary was built from, plus a `format` revision. Inflation is bounded
   so a hostile section cannot fill memory.
4. **Graph.** The root crate becomes the root node. The graph is walked
   from it, every reachable crate becomes a node built by the
   [Rust source decomposer](rust.md)'s node helper, and each edge takes
   the type of what it points at. Build dependencies, and everything only
   they pull in, are left out unless `--include-build` is set: they are
   what built the binary, not what runs in it. With networking, crates.io
   packages are enriched through the same client the source decomposer
   uses.
5. **Root.** The artifact unpacker wraps the result under a file node
   carrying the path and SHA-256 of the executable, related to the root
   crate with a `generatedFrom` edge. The parent that found the file
   decides how the file relates to it: an image `contains` it.

```
usr/local/bin/tool                          (file, sha256)
  └ generatedFrom ─▶ pkg:cargo/tool@1.2.3          (application)
                        ├ dependsOn ─▶ pkg:cargo/clap@4.5.4
                        │                 └ dependsOn ─▶ pkg:cargo/clap_builder@4.5.2
                        └ dependsOn ─▶ pkg:cargo/serde@1.0.197
```

## Data produced

### The root: the crate the binary was built from

| Field | Source | Notes |
|-------|--------|-------|
| Name, Version | the `root` package | `DecomposerOptions.Version` overrides the version |
| PURL | computed | `pkg:cargo/{name}@{version}` |
| Primary purpose | fixed | `APPLICATION` |
| `cargo:source` property | `source` | Set when the root is not from crates.io, which it never is: `local` for a workspace crate |
| `cargo-auditable:format` property | `format` | The record's format revision |
| VCS reference | `DecomposerOptions.CommitHash` | The record carries no VCS data; the caller may |

### Per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name, Version | record | |
| PURL | computed | `pkg:cargo/{name}@{version}` |
| Download URL | computed | `https://crates.io/api/v1/crates/{name}/{version}/download`, crates.io packages only |
| `cargo:source` property | `source` | Set for crates not from crates.io: `git`, `local`, `registry` or another value; the record holds no URL |
| License, description, homepage, repository, docs, size, MSRV | crates.io | With networking, crates.io packages only, as on the [Rust page](rust.md) |

The record carries **no checksums**. `Cargo.lock` does, and the source
decomposer reports them; a binary cannot.

## Where it runs

Like the [Go binary decomposer](gobinary.md), this one answers **images
and system roots** to the `api.SubjectDefaults` trait and not
**codebases**, and the same switches apply: `--skip-artifact rustbinary`
on either command, `--no-artifacts` on `unpack image`, and the
`ArtifactDecomposers` map on the image unpacker. The default skip list
for system directories applies too.

## Options

The decomposer has no options of its own. `DefaultOptions` returns the
Rust source decomposer's options, and driver options set for this
decomposer are read for `Concurrency`, the number of parallel crates.io
requests. The networking level comes from the artifact unpacker's options
(`--networking` on the CLI).

## Dependency types

| Common flag | Record equivalent | What it includes |
|-------------|-------------------|------------------|
| `--include-dev` | _(no-op)_ | Dev dependencies are not linked into a binary and are not recorded. |
| `--include-build` | `kind: build` | The build dependencies and their subtree, related through `buildDependency` edges. Off by default. |
| `--include-optional` | _(no-op)_ | Optional features that were enabled are ordinary dependencies in the record; the rest are absent. |

## Strengths

- **Ground truth with structure.** The record is what the linker used,
  and unlike Go build information it keeps the edges, so the graph is
  the real one without any network.
- **Works on the deployed thing.** No source, no `Cargo.lock`, no build.
- **Same shape as source.** Nodes come from the source decomposer's
  helper and enrichment goes through its client, so a binary and its
  project can be compared node for node.
- **Cheap.** One section read; the record for a large binary is a few
  kilobytes.

## Weaknesses

- **Opt-in at build time.** Only `cargo auditable build` writes the
  record. Most Rust binaries in the wild still lack it and are disowned.
- **No checksums.** Integrity has to come from `Cargo.lock` or the
  registry.
- **Sources without locations.** A `git` dependency is recorded as
  `git`, not as a URL and commit.
- **Executables only.** Fat Mach-O binaries and WebAssembly outputs,
  which cargo-auditable also supports, are not probed yet.

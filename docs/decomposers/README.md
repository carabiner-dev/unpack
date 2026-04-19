# Decomposers

Unpack ships with decomposers for four package ecosystems. Each decomposer
parses lock files and manifest files, resolves the dependency graph, and
produces a [protobom](https://github.com/protobom/protobom) NodeList that
can be serialized as SPDX or CycloneDX.

| Ecosystem | Entry point | Lock file | Manifest | Remote enrichment |
|-----------|------------|-----------|----------|-------------------|
| [Go](golang.md) | `source/golang/` | `go.sum` | `go.mod` | deps.dev API + Go module proxy |
| [Maven](maven.md) | `source/maven/` | _(none)_ | `pom.xml` | Maven Central |
| [npm](npm.md) | `source/npm/` | `package-lock.json` | `package.json` | _(none)_ |
| [Rust](rust.md) | `source/rust/` | `Cargo.lock` | `Cargo.toml` | crates.io API |

## Common capabilities

All decomposers share these behaviors:

- **Pure Go** -- no external binaries are required at runtime.
- **License normalization** -- license strings are mapped to SPDX identifiers
  via the shared `license` package.
- **Protobom output** -- every decomposer returns an `*sbom.NodeList` with
  typed edges (`dependsOn`, `devDependency`, `buildDependency`, etc.).
- **Commit hash injection** -- when `DecomposerOptions.CommitHash` is set,
  the root node receives a VCS external reference with the SHA-1 hash.
- **Version override** -- when `DecomposerOptions.Version` is set, the root
  node's version and PURL are updated accordingly.

## Per-decomposer docs

See the individual pages linked in the table above for implementation
details, data sources, and known limitations.

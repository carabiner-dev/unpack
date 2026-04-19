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

## Networking tiers

The `DecomposerOptions.Networking` field controls how much network access
decomposers are allowed. This is a top-level option that affects all
decomposers uniformly.

| Level | Value | Description |
|-------|-------|-------------|
| `NetworkEssential` | `0` (default) | Enables network calls essential for building the dependency tree plus lightweight metadata requests (deps.dev, checksum files, crates.io API). |
| `NetworkFull` | `1` | All of essential, plus downloading full artifacts for hash computation and zip archives for license classification. Prioritizes completeness over bandwidth. |
| `NetworkDisabled` | `-1` | No network calls. Only local data is used. Some decomposers will produce incomplete results (Go, Maven) while others work fully offline (npm, Rust without enrichment). |

### Per-decomposer networking behavior

| Call | disabled | essential | full |
|------|----------|-----------|------|
| **Go:** proxy .mod fetch (dependency graph) | skip | yes | yes |
| **Go:** deps.dev API (licenses, VCS) | skip | yes | yes |
| **Go:** proxy .zip download (license fallback) | skip | skip | yes |
| **Maven:** POM fetch (dependency tree) | skip | yes | yes |
| **Maven:** metadata fetch (snapshots, ranges) | skip | yes | yes |
| **Maven:** checksum files (.sha1, .sha256) | skip | yes | yes |
| **Maven:** artifact download (SHA-256/SHA-512) | skip | skip | yes |
| **npm:** _(none -- fully offline)_ | works | works | works |
| **Rust:** local parsing (Cargo.toml/lock) | works | works | works |
| **Rust:** crates.io API (enrichment) | skip | yes | yes |

## Per-decomposer docs

See the individual pages linked in the table above for implementation
details, data sources, and known limitations.

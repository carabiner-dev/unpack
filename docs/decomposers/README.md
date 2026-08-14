# Decomposers

Unpack ships with decomposers for five package ecosystems. Each decomposer
parses lock files and manifest files, resolves the dependency graph, and
produces a [protobom](https://github.com/protobom/protobom) NodeList that
can be serialized as SPDX or CycloneDX.

| Ecosystem | Entry point | Lock file | Manifest | Remote enrichment |
|-----------|------------|-----------|----------|-------------------|
| [Go](golang.md) | `source/golang/` | `go.sum` | `go.mod` | deps.dev API + Go module proxy |
| [Maven](maven.md) | `source/maven/` | _(none)_ | `pom.xml` | Maven Central |
| [JavaScript](npm.md) | `source/npm/` | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | `package.json` | _(none)_ |
| [Python](python.md) | `source/python/` | `uv.lock`, `poetry.lock`, `requirements.txt` | `pyproject.toml` (poetry only) | PyPI JSON API |
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
| **JavaScript:** _(none -- fully offline)_ | works | works | works |
| **Python:** local parsing (lockfiles, requirements) | works | works | works |
| **Python:** PyPI JSON API (licenses, metadata) | skip | yes | yes |
| **Rust:** local parsing (Cargo.toml/lock) | works | works | works |
| **Rust:** crates.io API (enrichment) | skip | yes | yes |

## Dependency inclusion flags

By default, only production/compile dependencies are included in the
output. Three flags control the inclusion of additional dependency types:

| Flag | CLI | Default | Description |
|------|-----|---------|-------------|
| `IncludeDev` | `--include-dev` | `false` | Include development and test dependencies |
| `IncludeBuild` | `--include-build` | `false` | Include build tool dependencies |
| `IncludeOptional` | `--include-optional` | `false` | Include optional dependencies |

### Per-decomposer mapping

| Flag | Go | Maven | npm | Python | Rust |
|------|-------|-------|-----|--------|------|
| `--include-dev` | _(no-op)_ | test-scoped deps | `devDependencies` (all lockfiles) | dependency groups (PEP 735) | `[dev-dependencies]` |
| `--include-build` | _(no-op)_ | `<build><plugins>` | _(no-op)_ | _(no-op)_ | `[build-dependencies]` |
| `--include-optional` | _(no-op)_ | `<optional>true</optional>` | `optionalDependencies` | extras | _(no-op)_ |

**Notes:**

- Go modules do not distinguish dependency types in `go.mod`, so all
  three flags are no-ops for the Go decomposer.
- Maven's scope transitivity rules still apply: a test-scoped dependency
  declared by one of your compile-scoped dependencies will never be
  included, even with `--include-dev`. The flag only affects dependencies
  declared directly in your own POM (or resolved at the current project
  level).
- npm's `peerDependencies` are not covered by these flags and remain
  a decomposer-specific option (`IncludePeerDependencies`).
- Maven's `provided` scope is not covered by these flags and remains
  a decomposer-specific option (`IncludeProvided`).
- Python resolves for one target environment (platform and interpreter
  version); see the [Python page](python.md) for the `--platform` and
  `--python-version` flags that pick it.
- Installed Python environments (site-packages) are read by a system
  decomposer that runs in image and filesystem scans, beside the rpm,
  deb and apk readers. See the [Python page](python.md).

## Per-decomposer docs

See the individual pages linked in the table above for implementation
details, data sources, and known limitations.

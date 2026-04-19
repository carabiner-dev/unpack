# Rust Decomposer

**Location:** `source/rust/`

## How it works

1. Parses `Cargo.toml` for root package metadata (name, version,
   license, edition) and the list of direct dependencies by type
   (normal, dev, build).
2. Parses `Cargo.lock` for the fully resolved dependency tree with
   exact versions, checksums, and source information.
3. Reconstructs the dependency graph by recursively resolving
   dependency references from the lock file, handling multiple
   versions of the same crate.
4. Enriches every dependency node by fetching metadata from the
   crates.io API (`/api/v1/crates/{name}/{version}`) in parallel.
5. Converts the graph to a protobom NodeList.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | `Cargo.lock` | Crate name |
| Version | `Cargo.lock` | Exact resolved version |
| PURL | computed | `pkg:cargo/{name}@{version}` |
| Download URL | computed | `https://crates.io/api/v1/crates/{name}/{version}/download` |
| Hash (SHA-256) | `Cargo.lock` | `checksum` field |
| License | crates.io API | Normalized to SPDX |
| Description | crates.io API | Short crate description |
| Homepage | crates.io API | Set as `UrlHome` |
| Repository | crates.io API | `ExternalReference_VCS` |
| Documentation | crates.io API | `ExternalReference_DOCUMENTATION` |
| Crate size | crates.io API | `Property` (`crates.io:crate_size`) |
| Rust version (MSRV) | crates.io API | `Property` (`crates.io:rust_version`) |

### Root node additional data

| Field | Source |
|-------|--------|
| License | `Cargo.toml` (`package.license`, normalized) |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `IncludeDevDependencies` | `bool` | `false` | Include dev dependencies |
| `IncludeBuildDependencies` | `bool` | `false` | Include build dependencies |
| `Concurrency` | `int` | `10` | Parallel crates.io API requests |

## Strengths

- **Rich metadata from crates.io.** Every dependency gets license,
  description, homepage, repository, documentation URL, crate size,
  and minimum Rust version -- all fetched in a single parallel batch.
- **Checksums from lock file.** `Cargo.lock` includes SHA-256
  checksums for every crate, verified by Cargo during builds.
- **Multiple version handling.** Correctly resolves cases where
  multiple versions of the same crate coexist in the dependency tree
  (e.g., `hashbrown 0.14` and `hashbrown 0.15`).
- **Dependency type classification.** Direct dependencies are
  classified as normal, dev, or build based on `Cargo.toml` sections,
  mapping to appropriate protobom edge types.
- **License normalization.** Both root (from `Cargo.toml`) and
  dependency licenses (from crates.io) are normalized to SPDX
  identifiers.

## Weaknesses

- **crates.io dependency.** Enrichment requires network access to the
  crates.io API. If the API is unreachable, dependency nodes will
  have checksums but no license, description, or other metadata.
- **No private registry support.** Only the public crates.io registry
  is supported. Crates from private registries or git sources will
  not be enriched.
- **Platform-specific dependencies.** `Cargo.lock` includes
  dependencies for all platforms. The decomposer includes all of
  them, which may be a superset of what builds on any single
  platform. This matches `cargo tree --all-targets` behavior.
- **No feature flag tracking.** Cargo's feature system affects which
  optional dependencies are included, but the decomposer does not
  track which features are active.
- **API rate limiting.** Large dependency trees generate many
  crates.io requests. While they run in parallel with configurable
  concurrency, very large projects may hit API rate limits.

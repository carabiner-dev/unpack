# Rust Decomposer

**Location:** `source/rust/`

## How it works

1. Parses `Cargo.toml` for root package metadata (name, version,
   license, edition) and the list of direct dependencies by type
   (normal, dev, build). A dependency declared under another name
   (`tmp = { package = "tempfile" }`) is known by the crate it renames,
   and one declared in several sections takes one type: normal over
   build over dev.
2. Reads the manifests of the project's other local packages: the
   members its `[workspace]` table lists, patterns expanded, and what
   those and the root require by path within the project. A member's
   own manifest is what says which of its dependencies are for
   development or building.
3. Parses `Cargo.lock` for the fully resolved dependency tree with
   exact versions, checksums, and source information.
4. Picks the roots among the local packages, those the lock gives no
   source. A project that is a single package is rooted at it, and a
   local package beside it is a path dependency. In a workspace the
   members are roots, the manifest's own package first; a local package
   that is no member and that something requires is a path dependency.
5. Reconstructs the dependency graph by recursively resolving
   dependency references from the lock file, handling multiple
   versions of the same crate. `Cargo.lock` does not say what kind a
   dependency is, so an edge takes the kind the manifest of the package
   it starts from declares, and no other package's.
6. Enriches every dependency node by fetching metadata from the
   crates.io API (`/api/v1/crates/{name}/{version}`), one crate at a
   time and a second apart, which is the pace the registry asks of
   automated clients. The client names itself in its `User-Agent`,
   without which crates.io refuses it.
7. Converts the graph to a protobom NodeList.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | `Cargo.lock` | Crate name |
| Version | `Cargo.lock` | Exact resolved version |
| PURL | computed | `pkg:cargo/{name}@{version}` |
| Download URL | computed | `https://crates.io/api/v1/crates/{name}/{version}/download` |
| Hash (SHA-256) | `Cargo.lock` | `checksum` field |
| License | crates.io API | Normalized to SPDX |
| Supplier | crates.io API | The account that published the version, by name or login, with its page. Absent for versions the registry names no publisher for; see [Suppliers](README.md#suppliers) |
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
| `Concurrency` | `int` | `10` | Kept for callers that set it; crates.io is asked one crate at a time |

## Dependency types

| Common flag | Rust equivalent | What it includes |
|-------------|----------------|------------------|
| `--include-dev` | `IncludeDevDependencies` | Crates listed in `[dev-dependencies]` in the `Cargo.toml` of the package the edge starts from, the root's or a workspace member's. The type is determined by checking `Cargo.toml` sections since `Cargo.lock` does not distinguish dependency types, and it applies to that package's edges only: the same crate required by another package at runtime stays in the graph. Edge type: `devDependency`. |
| `--include-build` | `IncludeBuildDependencies` | Crates listed in `[build-dependencies]` in `Cargo.toml`. These are typically proc-macro crates or build script helpers. Edge type: `buildDependency`. |
| `--include-optional` | _(no-op)_ | Cargo's `optional = true` flag on dependencies is related to feature gates, not optional installation. Not currently mapped. |

## Generation context

`source`. The decomposer reads `Cargo.lock` and `Cargo.toml` as they
stand in the source tree, before anything is built, so a document made
from its data is a source SBOM: CycloneDX lifecycle `pre-build`, SPDX 3
type `source`. A built binary is read by the
[Rust binary](rustbinary.md) decomposer, which reports `analyzed`. See
[Generation context](README.md#generation-context).

## Strengths

- **Rich metadata from crates.io.** Every dependency gets license,
  publisher, description, homepage, repository, documentation URL,
  crate size, and minimum Rust version from one request per crate.
- **Workspaces.** Every member roots the graph, once, and its
  dependencies are typed by its own manifest.
- **Checksums from lock file.** `Cargo.lock` includes SHA-256
  checksums for every crate, verified by Cargo during builds.
- **Multiple version handling.** Correctly resolves cases where
  multiple versions of the same crate coexist in the dependency tree
  (e.g., `hashbrown 0.14` and `hashbrown 0.15`).
- **Dependency type classification.** The direct dependencies of the
  root and of each workspace member are classified as normal, dev, or
  build based on their `Cargo.toml` sections, mapping to appropriate
  protobom edge types.
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
- **Enrichment is slow by design.** crates.io asks automated clients
  for no more than one request a second, so enriching a lockfile of some
  hundred crates takes minutes. When several requests in a row fail, the
  rest are not sent. `--networking disabled` skips enrichment.
- **`[workspace].exclude` is not read.** An excluded directory matched
  by a member pattern has its manifest used all the same.
- **Members are told from path dependencies by their manifests.** A
  manifest that cannot be found or read, or one a path leads to outside
  the project directory, leaves its package looking like a member: in a
  workspace it is then a root when nothing requires it.

# JavaScript Decomposer

**Location:** `source/npm/`

Reads JavaScript codebases from whichever lockfile their package manager
writes: `package-lock.json` (npm), `pnpm-lock.yaml` (pnpm, lock schemas 6
and 9), or `yarn.lock` in both its generations — classic (v1) and berry
(v2 onward), told apart by content, since both spell the file the same.

A codebase holding several is read in that order: npm's lock first, the
format this decomposer grew up on. Lockfiles vendored under
`node_modules` belong to installed dependencies and are never treated as
codebases. Every reader is held to its own tool by a conformance suite:
`npm ls`, `pnpm ls` and `yarn list`/`yarn info` all answer from the
lockfile, and the extracted packages and edges must agree with them.

## How each lockfile is read

### package-lock.json

`package.json` supplies the root's metadata and the direct dependencies
by kind; the lock (v2/v3) supplies the resolved tree, reconstructed from
its flattened `node_modules` paths, with exact versions, tarball URLs,
SRI integrity hashes and licenses per package.

### pnpm-lock.yaml

Both schema generations normalize into one shape: 6 (pnpm 8) prefixes
package keys with a slash and keeps edges on the package entries, 9
(pnpm 9 onward) moves the edges to a snapshots table. Peer-qualifier
suffixes are stripped everywhere. The lock's importers make workspaces
native: the project and every member root the graph with the identity
their own `package.json` states, and a `workspace:*` dependency is a
`link:` reference resolved from importer to importer. Integrity carries
over as hashes; licenses are only known for the importers, since the
lock records none.

### yarn.lock (classic)

One block per resolution, keyed by every `name@range` selector that
resolves to it, so edges resolve by exact lookup. The lock records no
dependency kinds at all: dev and optional come from `package.json`. SRI
integrity and resolved URLs carry over; when the integrity field lists
several hashes, the strongest is kept.

### yarn.lock (berry)

YAML entries keyed by protocol-carrying selectors, workspaces entries of
the lock itself. A berry lock knows even less about the project than a
classic one — workspace versions read `0.0.0-use.local` and dev
dependencies are flattened in unmarked — so each workspace's
`package.json` supplies identity and kinds. Virtual descriptors, the
peer-dependency clones, collapse onto one node each.

**Berry nodes carry no hashes and no download URL, deliberately**: the
lock's `checksum` covers yarn's own cache archive, which no registry or
attestation can reproduce, and a hash nothing else can verify identifies
nothing.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | lockfile | |
| Version | lockfile | Exact resolved version |
| PURL | computed | `pkg:npm/[@scope/]name@version` |
| Download URL | lockfile | Registry tarball URL; absent for berry |
| Hash | lockfile | SRI integrity (sha512/384/256/1), hex; absent for berry |
| License | `package-lock.json` only | The other lockfiles record none |

### Root node additional data

| Field | Source |
|-------|--------|
| Description | `package.json` |
| Homepage | `package.json` (as `ExternalReference_WEBSITE`) |
| Repository | `package.json` (as `ExternalReference_VCS`) |
| License | `package.json` (normalized) |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `IncludeDevDependencies` | `bool` | `false` | Include dev dependencies |
| `IncludeOptionalDependencies` | `bool` | `false` | Include optional dependencies |
| `IncludePeerDependencies` | `bool` | `false` | Include peer dependencies |
| `IgnoreNodeModulesCodebases` | `bool` | `true` | Ignore package-lock.json in node_modules |

## Dependency types

| Common flag | npm equivalent | What it includes |
|-------------|---------------|------------------|
| `--include-dev` | `IncludeDevDependencies` | Packages listed in `devDependencies` in `package.json`. These are direct dependencies only — transitive deps of dev dependencies are still included if they are also reachable from production deps. Edge type: `devDependency`. |
| `--include-build` | _(no-op)_ | npm does not have a separate build dependency concept. |
| `--include-optional` | `IncludeOptionalDependencies` | Packages listed in `optionalDependencies` in `package.json`. Edge type: `optionalDependency`. |

`peerDependencies` are not covered by the common flags and remain a
decomposer-specific option.

## Strengths

- **No network requests.** All data comes from local files.
  `package-lock.json` already contains resolved URLs, integrity
  hashes, and license identifiers for every dependency.
- **Strong hashes.** npm uses SHA-512 by default for integrity
  checks, providing high-quality cryptographic hashes out of the box.
- **Fast.** No HTTP fetching means decomposition completes in
  milliseconds even for large trees.
- **Scoped package support.** Correctly handles `@scope/name`
  packages in both PURL generation and dependency resolution.

## Weaknesses

- **npm lockfile v1 not supported.** Only lockfile versions 2 and 3
  (with the `packages` key) are supported, and only pnpm lock schemas
  6 and 9. Older files need regenerating with a modern tool.
- **No remote enrichment.** Unlike Maven and Rust, the JavaScript
  decomposer does not fetch registry metadata. Dependency licenses are
  only known where a lockfile records them, which only
  `package-lock.json` does.
- **License field limitations.** `package-lock.json` only includes a
  simple `license` string. Packages with complex license expressions
  in their own `package.json` (e.g., `(MIT OR Apache-2.0)`) may be
  simplified or missing in the lock file.
- **Berry hashes.** A berry lock's checksums cannot be tied to registry
  artifacts, so those nodes carry none — an honest gap rather than an
  unverifiable value.
- **npm workspaces.** pnpm and yarn berry workspaces are read natively,
  every member a root. npm's own workspaces (in package-lock.json) are
  not explicitly handled yet.

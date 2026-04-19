# npm Decomposer

**Location:** `source/npm/`

## How it works

1. Parses `package.json` for root package metadata (name, version,
   description, license, homepage, repository) and the list of
   direct dependencies by type (normal, dev, peer, optional).
2. Parses `package-lock.json` (lockfile v2/v3 format) which contains
   the fully resolved dependency tree with exact versions, download
   URLs, integrity hashes, and licenses for every package.
3. Reconstructs the dependency graph from the flattened lock file
   entries, mapping nested `node_modules` paths to parent-child
   relationships.
4. Converts the graph to a protobom NodeList.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | `package-lock.json` | Extracted from `node_modules/` path |
| Version | `package-lock.json` | Exact resolved version |
| PURL | computed | `pkg:npm/[@scope/]name@version` |
| Download URL | `package-lock.json` | `resolved` field (registry tarball URL) |
| Hash | `package-lock.json` | `integrity` field (SRI format: sha512/384/256/1) |
| License | `package-lock.json` | Normalized to SPDX |

### Root node additional data

| Field | Source |
|-------|--------|
| Description | `package.json` |
| Homepage | `package.json` (as `ExternalReference_WEBSITE`) |
| Repository | `package.json` (as `ExternalReference_VCS`) |
| License | `package.json` (normalized) |

## Options

The npm decomposer currently has no ecosystem-specific options beyond
the common `DecomposerOptions`.

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

- **Lockfile v1 not supported.** Only lockfile versions 2 and 3
  (with the `packages` key) are supported. Projects using the older
  `dependencies`-keyed format need to regenerate their lockfile with
  a modern npm version.
- **No remote enrichment.** Unlike Maven and Rust, the npm decomposer
  does not fetch additional metadata from the registry. Description,
  homepage, and repository are only available for the root package
  (from `package.json`), not for dependencies.
- **License field limitations.** `package-lock.json` only includes a
  simple `license` string. Packages with complex license expressions
  in their own `package.json` (e.g., `(MIT OR Apache-2.0)`) may be
  simplified or missing in the lock file.
- **Workspace support.** npm workspaces (monorepos) are not explicitly
  handled. Each workspace package would need to be decomposed
  separately.

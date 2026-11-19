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

In a project declaring `workspaces`, every project directory the lock
has an entry for is a workspace member and roots the graph beside the
project itself, with the dependencies its own lock entry declares,
resolved from where the member sits: its own nested copy of a package
when it has one, the hoisted one otherwise. A link in `node_modules`
resolves to the directory it points at, so a dependency on a member
reaches the member's node, and a `file:` dependency of a project
without workspaces is an ordinary dependency with its own version and
dependencies. The lock does not tell a member from a directory required
by path, so with workspaces every local directory is taken for a member.

### pnpm-lock.yaml

Both schema generations normalize into one shape: 6 (pnpm 8) prefixes
package keys with a slash and keeps edges on the package entries, 9
(pnpm 9 onward) moves the edges to a snapshots table. pnpm installs a
package once per set of peers it is resolved against and writes an entry
for each, its key suffixed with the peers (`plug@1.0.0(host@2.0.0)`):
they are one package at one version and so one node, whose edges are the
union of its variants', a dependency the variants resolve differently
getting an edge to each version. An aliased dependency, whose reference
is the key of another package (`pad: lodash.padstart@4.6.1`), resolves
to that package's node. The lock's importers make workspaces
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
several hashes, the strongest is kept. A package installed under another
name (`pad@npm:lodash.padstart@^4.6.1`) is the node of the package
installed, named after it.

### yarn.lock (berry)

YAML entries keyed by protocol-carrying selectors, workspaces entries of
the lock itself. A berry lock knows even less about the project than a
classic one — workspace versions read `0.0.0-use.local` and dev
dependencies are flattened in unmarked — so each workspace's
`package.json` supplies identity and kinds. Virtual descriptors, the
peer-dependency clones, collapse onto one node each. Both spellings of a
dependency are read: Yarn 4 writes the selector with its protocol
(`"npm:^2.1.3"`), Yarn 2 and 3 a bare range (`^2.1.3`) against an entry
keyed with it. A node is named after the package its entry resolves to,
which is what an alias or a patched package is really.

**Berry nodes carry no hashes and no download URL, deliberately**: the
lock's `checksum` covers yarn's own cache archive, which no registry or
attestation can reproduce, and a hash nothing else can verify identifies
nothing.

### Peer dependencies

A peer dependency is a package another needs and leaves to its host to
bring. With `package-lock.json`, which records them:

- **Of an installed package:** npm installs it at the host's level, and
  when the lock holds it there the package depends on it like on any
  other (`dependsOn`). One that is not installed, as an optional peer
  may not be, gets no edge.
- **Of the project or a workspace member:** npm installs those too, but
  the project does not bring them: whoever uses it does. The edge is a
  `providedDependency`. A peer that is also a dev dependency is a dev
  dependency.

The pnpm lock already lists resolved peers among a package's
dependencies; Yarn's locks do not record a project's own.

### Suppliers, licenses and the registry

A lock says where a package was fetched from and little or nothing about
who is behind it or how it is licensed, so with networking enabled each
package of the public npm registry is asked about there
(`/{name}/{version}`, ten requests at a time). Two things are read from
the answer:

- **The supplier:** the author the package's manifest declares, or, for
  the many packages that declare none, the account that published the
  version.
- **The license,** for a package whose lock recorded none, which is every
  package of a pnpm or yarn lock. It is the manifest's `license`, an
  SPDX identifier or expression, or the object and list forms older
  manifests used, normalized through the shared license catalog. What
  `package-lock.json` recorded stands. Two values npm gives a meaning
  of its own state no license: `UNLICENSED`, which says none is granted,
  and `SEE LICENSE IN <file>`, which points at a file that is not read.

Only packages of the public registry are asked about, so the name of a
package from anywhere else is never sent to it:

- **`package-lock.json`, classic `yarn.lock`:** the lock states each
  package's download URL. It is asked about when that is on
  `registry.npmjs.org` or Yarn's mirror `registry.yarnpkg.com`, over
  https.
- **`pnpm-lock.yaml`, berry `yarn.lock`:** the lock does not say, the
  configuration does. The default registry and the registry of each
  scope are read from the user's and the project's `.npmrc` (and
  `pnpm-workspace.yaml`) or `.yarnrc.yml`, and from the environment
  (`npm_config_registry`, `YARN_NPM_REGISTRY_SERVER`); a package is asked
  about when they leave it on the public registry. A configuration that
  cannot be read, or a registry left to a `${VARIABLE}`, settles it the
  cautious way: nothing is asked. A pnpm entry with a tarball URL is
  judged by that URL, and a berry entry not resolved through the `npm:`
  protocol (a patch, a repository, a directory) is never asked about.
- **Never:** the project's own packages, workspace members, and
  `link:` or `file:` dependencies.

What the configuration cannot show is a registry given on an install
command line, or set on the machine that made the lock and not on the
one reading it.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | lockfile | |
| Version | lockfile | Exact resolved version |
| PURL | computed | `pkg:npm/[@scope/]name@version` |
| Download URL | lockfile | Registry tarball URL; absent for berry |
| Hash | lockfile | SRI integrity (sha512/384/256/1), hex; absent for berry |
| License | `package-lock.json` / npm registry | The lock's when it records one, which only `package-lock.json` does; the registry's otherwise, with networking, for public-registry packages |
| Supplier | npm registry | The declared author, else the publishing account. Needs networking, public-registry packages only; see above |

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
| `IncludePeerDependencies` | `bool` | `false` | Declared, and not read by any of the lock readers: peers are handled as [described above](#peer-dependencies) |
| `IgnoreNodeModulesCodebases` | `bool` | `true` | Ignore package-lock.json in node_modules |

## Dependency types

| Common flag | npm equivalent | What it includes |
|-------------|---------------|------------------|
| `--include-dev` | `IncludeDevDependencies` | Packages listed in `devDependencies` in `package.json`. These are direct dependencies only — transitive deps of dev dependencies are still included if they are also reachable from production deps. A package listed in both `dependencies` and `devDependencies` is a runtime dependency. Edge type: `devDependency`. |
| `--include-build` | _(no-op)_ | npm does not have a separate build dependency concept. |
| `--include-optional` | `IncludeOptionalDependencies` | Packages listed in `optionalDependencies` in `package.json`. Edge type: `optionalDependency`. |

`peerDependencies` are not covered by the common flags; see
[Peer dependencies](#peer-dependencies).

## Generation context

`source`, for every lock file. The decomposer reads the lock and its
manifests as they stand in the source tree, before anything is built or
installed, so a document made from its data is a source SBOM: CycloneDX
lifecycle `pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Strengths

- **The graph needs no network.** Versions, edges and hashes come from
  local files. `package-lock.json` already contains resolved URLs,
  integrity hashes, and license identifiers for every dependency. Only
  suppliers, and the licenses a lock does not record, are fetched.
- **Workspaces in every lock format.** npm, pnpm and yarn berry
  workspaces are read natively, every member a root.
- **Private names stay private.** The registry is only asked about
  packages their lock or the project's configuration places on the
  public registry.
- **Strong hashes.** npm uses SHA-512 by default for integrity
  checks, providing high-quality cryptographic hashes out of the box.
- **Fast.** With networking disabled, decomposition completes in
  milliseconds even for large trees.
- **Scoped package support.** Correctly handles `@scope/name`
  packages in both PURL generation and dependency resolution.

## Weaknesses

- **npm lockfile v1 not supported.** Only lockfile versions 2 and 3
  (with the `packages` key) are supported, and only pnpm lock schemas
  6 and 9. Older files need regenerating with a modern tool.
- **pnpm and yarn licenses need the network.** Their locks record none,
  so with networking disabled those nodes have no license; the same
  goes for a package of a private registry, a repository or a path,
  which the public registry is never asked about.
- **A supplier may be an account name.** For a package declaring no
  author, the supplier is the npm account that published it, such as
  `react-bot`, which is not the name an entity goes by.
- **License field limitations.** `package-lock.json` only includes a
  simple `license` string. Packages with complex license expressions
  in their own `package.json` (e.g., `(MIT OR Apache-2.0)`) may be
  simplified or missing in the lock file, and what the lock recorded is
  kept as it is. `UNLICENSED` and `SEE LICENSE IN <file>` leave a node
  with no license.
- **Berry hashes.** A berry lock's checksums cannot be tied to registry
  artifacts, so those nodes carry none — an honest gap rather than an
  unverifiable value.
- **Classic yarn workspaces.** A classic `yarn.lock` does not record
  workspace members, and only the root `package.json` is read, so the
  members' own dependencies are not walked from them.

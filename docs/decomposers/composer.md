# PHP (Composer) Decomposer

**Location:** `source/composer/` (codebases), `system/composer/` (installed
environments)

Reads PHP codebases managed by [Composer](https://getcomposer.org/), from
`composer.lock`, and installed Composer environments — the
`vendor/composer/installed.json` a deployment or container image carries.
The lockfile is the richest in mainstream use: resolved versions, the
dependency graph, licenses, descriptions, homepages and the exact git
commit of every package are all in it, so extraction is offline end to
end, and **licenses need no network at all** — a first among the lockfile
ecosystems.

## How it works

### composer.lock

The manifest (`composer.json`) supplies what the lock does not: the
project's identity and which requirements are direct, with `require-dev`
walked only under `--include-dev`. The lock supplies everything else, and
the graph is walked from the manifest's requirements through each
package's own `require` table.

Platform requirements — `php` itself, `ext-*` extensions, the composer
APIs — are constraints on the runtime rather than packages: every real
package is `vendor/name`, platform names carry no slash, and they become
nothing.

### Installed environments

The system decomposer runs in image and filesystem scans beside the OS
package readers, walking for `*/composer/installed.json`. Its entries are
the lockfile's own shape, so an installed environment is a lock found in
place: when the project's `composer.json` sits above the vendor directory
— the layout deployments have — the graph builds exactly as for a
codebase, root and direct requirements included. Without a manifest,
whatever nothing installed requires roots the graph, and the file's own
`dev-package-names` partition tells the kinds. Both generations of the
file are read (Composer 2's object, Composer 1's bare array), and a
filesystem holding several vendor directories merges them into one graph.

A caveat worth knowing: a vendor tree inside an archive is invisible to a
filesystem walk. The `composer:2` image itself scans to nothing, because
Composer ships as a phar.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | lock / installed.json | `vendor/name` |
| Version | lock / installed.json | As locked, `v` prefixes kept |
| PURL | computed | `pkg:composer/{vendor}/{name}@{version}` |
| Download URL | `dist.url` | The installable archive |
| Repository | `source` | `ExternalReference_VCS`, with the exact commit: `url#reference` |
| Hash (SHA-1) | `dist.shasum` | Only when a registry states one — Packagist does not; see below |
| License | lock / installed.json | Normalized to SPDX; offline |
| Description | lock / installed.json | |
| Homepage | lock / installed.json | Set as `UrlHome` |

### Integrity

Packagist states no archive hashes: its archives are built from the
source commit, and **the commit is the integrity anchor**. Every node
carries its repository reference down to the commit; an archive SHA-1
appears only when a registry actually states one, which some private
registries do.

## Dependency types

| Common flag | Composer equivalent | What it includes |
|-------------|--------------------|--------------------|
| `--include-dev` | `require-dev` | The manifest's dev requirements and what they pull in. In an installed environment without a manifest, the `dev-package-names` partition. Edge type: `devDependency`. |
| `--include-build` | _(no-op)_ | Composer has no build dependency concept. |
| `--include-optional` | _(no-op)_ | Composer's `suggest` entries are recommendations, not resolved dependencies, and are not read. |

## Conformance

The reader is held to `composer show --locked`, which answers from the
lockfile alone: the package set must agree, and so must which packages
are direct — composer flags them, and ours are the targets of the root's
edges. The oracle runs in Docker like the Maven one.

## Strengths

- **Fully offline, licenses included.** Everything an SBOM wants is in
  the lock or the installed metadata.
- **Commit-level provenance.** Every package names its repository and
  the exact commit it was resolved from.
- **Deployments and images.** The installed-environment reader means a
  PHP container reports its packages next to the OS inventory, licenses
  and all.

## Weaknesses

- **No archive hashes from Packagist.** The commit is the anchor; nodes
  carry an archive SHA-1 only when a registry states one.
- **`suggest` is not read.** Optional integrations are recommendations
  Composer does not resolve, so there is nothing locked to report.
- **Vendor trees inside archives are invisible.** A phar-packaged
  application scans to nothing, honestly.

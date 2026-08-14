# Ruby (Bundler) Decomposer

**Location:** `source/ruby/`

Reads Ruby codebases managed by [Bundler](https://bundler.io/), from
`Gemfile.lock`. The lock carries the resolved graph inline — every spec
lists its dependencies — and, when written with checksums (Bundler 2.6's
`bundle lock --add-checksums`), the sha256 of every artifact. Licenses are
not in the lock and come from rubygems.org with networking enabled.

## How it works

1. Parses `Gemfile.lock`: the registry, git and path source blocks with
   their specs, the direct dependency set, the platforms, and the
   checksums when present. A git source carries the exact resolved
   commit.
2. Selects each gem's variant for the target platform. A gem may resolve
   once per platform (`ffi (1.17.4-x86_64-linux-gnu)`), and the builder
   picks the native build for the target — glibc preferred, musl never
   chosen, the same assumption the Python wheel selection makes — with
   the pure-Ruby variant as the fallback. The checksum follows the
   selected artifact: one lock yields a different ffi hash per target.
3. Walks the graph from the direct dependencies; a spec's dependency
   names are the edges, since the lock resolves a name to one version.
4. With networking enabled, enriches registry gems from the rubygems.org
   version-exact API: licenses, descriptions, homepages, repositories,
   and — for locks without checksums — the pure-Ruby artifact's sha256,
   which never displaces a checksum the lock stated and never lands on a
   platform-variant node it does not hash.

## Targeting a platform

The generic `--platform os[/arch]` flag selects among a gem's platform
variants, its third consumer after Python and the flag's design. The
variant travels in the purl as a qualifier:

```
--platform linux/amd64   →  pkg:gem/ffi@1.17.4?platform=x86_64-linux-gnu
--platform darwin/arm64  →  pkg:gem/ffi@1.17.4?platform=arm64-darwin
--platform windows/amd64 →  pkg:gem/ffi@1.17.4   (no mingw build locked)
```

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | `Gemfile.lock` | |
| Version | `Gemfile.lock` | The platform suffix becomes a purl qualifier |
| PURL | computed | `pkg:gem/{name}@{version}[?platform=...]` |
| Download URL | computed | `{remote}/downloads/{name}-{full version}.gem`; a git source's URL with its commit |
| Hash (SHA-256) | `Gemfile.lock` / rubygems.org | The selected artifact's checksum; see above |
| Repository | git source / rubygems.org | `ExternalReference_VCS`; git gems include the resolved commit |
| License | rubygems.org | Normalized to SPDX; needs networking |
| Description | rubygems.org | |
| Homepage | rubygems.org | Set as `UrlHome` |

## Dependency types

| Common flag | Bundler equivalent | What it includes |
|-------------|-------------------|--------------------|
| `--include-dev` | _(no-op)_ | The lock does not know groups: the Gemfile is executable Ruby, so `DEPENDENCIES` lists every direct gem unmarked and all of them are always included. |
| `--include-build` | _(no-op)_ | Bundler has no build dependency concept. |
| `--include-optional` | _(no-op)_ | Bundler has no optional dependency concept. |

## Conformance

The reader is held to Bundler's own lockfile parser, run over the same
locks in Docker: the gem set, every resolved version, the direct
dependency set and the edges must all agree with what
`Bundler::LockfileParser` reads. No install and no network — the parser
is the library Bundler ships with.

## Strengths

- **The graph is in the lock.** Versions, edges and provenance need no
  network; with checksums enabled, hashes too.
- **Platform-aware.** The variant selection means each target's SBOM
  hashes the artifact that target actually installs.
- **Commit-level provenance for git gems.**

## Weaknesses

- **No dev split.** Which direct gems are development-only lives in the
  Gemfile's Ruby code, which is not executed or parsed: every declared
  gem is included, honestly over-reporting rather than guessing.
- **Licenses need the network.** The lock carries none; with networking
  disabled, every node is license-empty.
- **Hashes need a checksums lock.** Bundler writes CHECKSUMS on request
  (2.6+); without it, only the registry can supply hashes, and only for
  pure-Ruby artifacts.
- **Linux assumes glibc.** Variant selection prefers gnu builds and
  never chooses musl ones.

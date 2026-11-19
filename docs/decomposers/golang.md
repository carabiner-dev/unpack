# Go Decomposer

**Location:** `source/golang/`

## How it works

1. Parses `go.mod` to extract the module path, Go version, the
   requirements, direct and `// indirect`, replace directives, and
   exclude directives.
2. Settles which modules are in the build, and at which version. From
   Go 1.17 on, `go.mod` lists every module the build needs at the
   version selected, so its requirements are the whole set and `go.sum`
   only supplies `h1:` hashes (SHA-256 dirhash of each module zip). An
   older `go.mod` lists little more than the direct requirements; there
   the rest comes from `go.sum`, each module at the highest version
   recorded for its path, which is the one Go selects, and only when
   `go.sum` holds the module's own hash and not just its `go.mod`'s.
3. Fetches `go.mod` files for every module of the set from the
   Go module proxy (`proxy.golang.org` by default) to reconstruct
   the dependency graph: a requirement becomes an edge when its target
   is in the set. Fetches run in parallel with configurable
   concurrency.
4. Converts the graph into a protobom NodeList. Only the direct
   requirements hang off the root. An indirect one hangs under the
   module that requires it, and off the root only when no module's
   `go.mod` reaches it, so that it is not lost.
5. Enriches dependency nodes with license and source repository data
   from the [deps.dev API](https://docs.deps.dev/api/v3/). With
   `NetworkFull`, also falls back to downloading module zips from the
   proxy for any modules not found in deps.dev, extracting the LICENSE
   file, and classifying it with `google/licenseclassifier/v2`.

## The root's version

When the codebase is a git repository, the root is versioned the way the
go command would name that commit, so its identifier is one Go tooling
recognizes:

- A commit carrying a version tag is that version.
- Any other is known by its
  [pseudo-version](https://go.dev/ref/mod#pseudo-versions), built from
  the commit's time and hash and the highest version tagged before it in
  its history: `v1.2.4-0.20260102150405-abcdefabcdef` after `v1.2.3`,
  `v1.2.3-rc.1.0.20260102150405-abcdefabcdef` after a pre-release, and
  `v0.0.0-20260102150405-abcdefabcdef` when nothing was tagged before.

A tag counts when it is a canonical semantic version of the major
version the module path states: `v0` or `v1` with no suffix, `v2` for a
path ending in `/v2`. Tags on other branches are not in the commit's
history and are ignored.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | `go.mod` / graph | Module path |
| Version | `go.mod` / `go.sum` | Resolved version after replace/exclude |
| PURL | computed | `pkg:golang/{module}@{version}` |
| Download URL | computed | `https://proxy.golang.org/{module}/@v/{version}.zip` |
| Hash (SHA-256) | `go.sum` | `h1:` dirhash -- hash of the module zip's file tree, not raw bytes |
| License | deps.dev / LICENSE file | deps.dev provides pre-classified SPDX identifiers; zip fallback uses `google/licenseclassifier/v2` |
| Source repo | deps.dev | `ExternalReference_VCS` from deps.dev `SOURCE_REPO` link |
| Supplier | module path | Whoever controls the path: the repository owner on a code host, with its URL (`spf13`, `https://github.com/spf13`), the domain otherwise (`golang.org`). `gopkg.in` resolves to the GitHub owner it redirects to. Offline; see [Suppliers](README.md#suppliers) |

## Special nodes

- **stdlib** -- a synthetic dependency with PURL `pkg:golang/stdlib@{go version}`,
  license `BSD-3-Clause` and supplier `The Go Authors`, added when
  `go.mod` declares a `go` directive.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `IncludeGo` | `bool` | `true` | Include the stdlib node |
| `ProxyURL` | `string` | `https://proxy.golang.org` | Go module proxy URL |
| `HTTPClient` | `*http.Client` | _(default)_ | Custom HTTP client (for testing) |
| `Concurrency` | `int` | `10` | Parallel proxy/deps.dev requests |

## Dependency types

Go modules do not distinguish between production, dev, build, or optional
dependencies in `go.mod`. All three common flags (`--include-dev`,
`--include-build`, `--include-optional`) are no-ops for the Go decomposer.
All declared dependencies are always included.

## Generation context

`source`. The decomposer reads `go.mod` and `go.sum` as they stand in the
source tree, before anything is built, so a document made from its data
is a source SBOM: CycloneDX lifecycle `pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Strengths

- No external tooling needed -- does not shell out to `go`.
- Handles replace and exclude directives correctly.
- Hashes come directly from `go.sum`, which is verified by the
  Go checksum database.
- The transitive graph is reconstructed by fetching upstream `go.mod`
  files, within the modules the build actually holds, each at the
  version the build selected. The output is the same on every run.
- Direct and indirect requirements are told apart, so the root's
  dependencies are the ones the module itself declares.
- The root is versioned as Go versions it, by tag or pseudo-version.
- License enrichment is fast: deps.dev responses are ~500 bytes each
  and provide pre-classified SPDX identifiers.
- Source repository URLs are extracted from deps.dev for free.

## Weaknesses

- **`h1:` hashes are dirhashes, not file hashes.** The SHA-256 value
  is a hash of a sorted file-content tree, not the raw zip bytes.
  Tools that expect a plain file checksum may not be able to verify it.
- **Proxy/API dependency.** If the Go proxy and deps.dev are both
  unreachable, the transitive graph will be incomplete and dependency
  nodes will lack license data.
- **Zip fallback is heavier.** With `NetworkFull`, for modules not
  indexed by deps.dev, the full module zip is downloaded to extract
  and classify the LICENSE file. This is rare for public modules but
  adds bandwidth for private or very new packages.
- **Older modules report a superset.** A `go.mod` declaring Go below
  1.17, or no version, does not list its whole build, and `go.sum` also
  records modules only the tests of dependencies need. Versions are
  right; some modules listed are not compiled in.
- **The supplier is an identifier.** Nothing in Go declares an author or
  an organization, so the supplier is who controls the module path: an
  account or a domain, not the name an entity goes by.
- **Subdirectory modules get no git version.** The version is read from
  git only when the codebase is at the repository's root.

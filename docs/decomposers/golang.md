# Go Decomposer

**Location:** `source/golang/`

## How it works

1. Parses `go.mod` to extract the module path, Go version, direct
   dependencies, replace directives, and exclude directives.
2. Parses `go.sum` to discover transitive dependencies and extract
   `h1:` hashes (SHA-256 dirhash of each module zip).
3. Fetches `go.mod` files for every resolved dependency from the
   Go module proxy (`proxy.golang.org` by default) to reconstruct
   the full dependency graph. Fetches run in parallel with
   configurable concurrency.
4. Converts the graph into a protobom NodeList.
5. Enriches dependency nodes with license and source repository data
   from the [deps.dev API](https://docs.deps.dev/api/v3/). With
   `NetworkFull`, also falls back to downloading module zips from the
   proxy for any modules not found in deps.dev, extracting the LICENSE
   file, and classifying it with `google/licenseclassifier/v2`.

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

## Special nodes

- **stdlib** -- a synthetic dependency with PURL `pkg:golang/stdlib@{go version}`,
  license `BSD-3-Clause`, added when `go.mod` declares a `go` directive.

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

## Strengths

- No external tooling needed -- does not shell out to `go`.
- Handles replace and exclude directives correctly.
- Hashes come directly from `go.sum`, which is verified by the
  Go checksum database.
- Full transitive graph is reconstructed by fetching upstream `go.mod`
  files, matching the behavior of `go mod graph`.
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

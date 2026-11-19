# Decomposers

Unpack ships with decomposers for seven package ecosystems. Each decomposer
parses lock files and manifest files, resolves the dependency graph, and
produces a [protobom](https://github.com/protobom/protobom) NodeList that
can be serialized as SPDX or CycloneDX.

| Ecosystem | Entry point | Lock file | Manifest | Remote enrichment |
|-----------|------------|-----------|----------|-------------------|
| [Go](golang.md) | `source/golang/` | `go.sum` | `go.mod` | deps.dev API + Go module proxy |
| [Maven](maven.md) | `source/maven/` | _(none)_ | `pom.xml` | Maven Central |
| [PHP (Composer)](composer.md) | `source/composer/` | `composer.lock` | `composer.json` | _(none — licenses and authors are in the lock)_ |
| [JavaScript](npm.md) | `source/npm/` | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | `package.json` | npm registry (suppliers, licenses) |
| [Python](python.md) | `source/python/` | `uv.lock`, `poetry.lock`, `requirements.txt` | `pyproject.toml` (poetry only) | PyPI JSON API |
| [Ruby (Bundler)](ruby.md) | `source/ruby/` | `Gemfile.lock` | _(not read — executable Ruby)_ | rubygems.org API |
| [Rust](rust.md) | `source/rust/` | `Cargo.lock` | `Cargo.toml` | crates.io API |
| [sbt](sbt.md) | `source/sbt/` | _(a GitHub dependency snapshot, given with `--sbt-snapshot`)_ | _(not read — executable Scala)_ | _(none)_ |

## Artifact decomposers

Built artifacts can carry their own dependency data. The artifact
unpacker (`artifact/`) probes files for the formats these decomposers
understand, on their own through `unpack artifact` and inside every
container image `unpack image` scans.

| Artifact | Entry point | Reads | Runs by default under | Remote enrichment |
|----------|------------|-------|-----------------------|-------------------|
| [Go executables](gobinary.md) | `artifact/gobinary/` | Embedded build information (`debug/buildinfo`) | images, system roots; not codebases | Go module proxy + deps.dev, through the Go decomposer |
| [Rust executables](rustbinary.md) | `artifact/rustbinary/` | The cargo-auditable record (`.dep-v0` section) | images, system roots; not codebases | crates.io API, through the Rust decomposer |

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
  node's version and PURL are updated accordingly. The Go decomposer names
  a commit the way Go does instead, by its tag or its pseudo-version; see
  the [Go page](golang.md#the-roots-version).
- **Suppliers** -- every decomposer names who each dependency is supplied
  by, from the best source its ecosystem has. See [Suppliers](#suppliers).
- **Generation context** -- every decomposer says at what point of the
  software's life it reads, and the document written from its data states
  it. See [Generation context](#generation-context).

## Generation context

An SBOM is expected to say in what context it was generated: what there
was to read when it was made. A document made from a lock file in a source
tree and one made by taking a built binary apart can describe the same
software and still be different statements, and a reader weighs them
differently. The contexts are the
[SBOM types CISA defines](https://www.cisa.gov/resources-tools/resources/types-software-bill-materials-sbom).

The context is the decomposer's to state, not the command's: each
decomposer implements `api.ContextReporter` and names the one it reads in.

| Context | Meaning | Decomposers |
|---------|---------|-------------|
| `source` | Read from a source tree and the manifests and lock files in it, before anything is built | Go, Maven, JavaScript, PHP, Python, Ruby, Rust |
| `build` | Read from what the build tool recorded of its own dependency resolution | sbt |
| `analyzed` | Read by taking apart something already built | Go binary, Rust binary, the release reader, and the system readers (rpm, deb, apk, installed Python environments, Composer vendor directories) |

### How it reaches the document

A decomposer returns a NodeList, which holds components and nothing about
how they were read. The unpacker that ran it pairs each NodeList with its
context in an `api.Extraction`, and the command writing the document takes
it from there:

| Format | Where the context is written |
|--------|------------------------------|
| CycloneDX | `metadata.lifecycles`: `pre-build` for source, `build`, `post-build` for analyzed |
| SPDX 3 | The SBOM element's `software_sbomType`: `source`, `build`, `analyzed` |
| SPDX 2.3 | The document comment, as a sentence (`SBOM type: source. ...`). The format has no field for it, and the comment is only written when the document has none |

### What each unpacker reports

| Unpacker | Command | Contexts of a graph |
|----------|---------|---------------------|
| Codebases (`dependencies/`) | `unpack extract` | The context of the decomposer that read the codebase |
| Artifacts (`artifact/`) | `unpack artifact` | The context of the decomposer that claimed the file |
| Images (`image/`) | `unpack image` | `analyzed`, since an image is something built being taken apart, plus the contexts of whatever the system and artifact decomposers find inside it |
| Releases (`release/`) | `unpack release` | The context of the release reader |
| SBOMs (`sbom/`) | `unpack sbom` | The types the document that is read states itself; nothing when it states none |

Things that follow from this:

- **A document can state more than one type.** A graph assembled from
  decomposers reading in different contexts carries each of them, once.
  All three formats take a list; in SPDX 2.3 the comment has a sentence
  for each.
- **A document can state none.** A decomposer or an unpacker written
  outside this repository that does not implement the interfaces says
  nothing, and nothing is guessed in its place.
- **A re-read SBOM keeps its type, with limits.** `unpack sbom` passes on
  the types of the document it reads, whichever they are, including the
  ones no decomposer here reads in (`design`, `deployed`, `runtime` and
  CycloneDX's `discovery` and `decommission`). Three things are lost:
  an SPDX 2.3 document carries no type to read, not even the comment
  unpack itself writes there; a CycloneDX lifecycle given as a custom name
  instead of a phase is dropped; and the types of documents stitched in
  with `--add-sbom` are not merged.
- **Not every type exists in every format.** SPDX 3 has no type for
  `discovery` or `decommission`, so a CycloneDX document marked with
  either loses it when converted to SPDX 3.

## Suppliers

An SBOM is expected to name the supplier of each component. No lock file
records one, so each decomposer takes it from the best source its
ecosystem has: what the package or its registry declares where there is
such a thing, and who controls the package's name where there is not.

| Ecosystem | A dependency's supplier | Needs the network |
|-----------|-------------------------|-------------------|
| Go | Whoever controls the module's path: the repository owner on a code host (`github.com/spf13`), the domain otherwise (`golang.org`); `gopkg.in` resolves to the GitHub owner it redirects to | No |
| sbt | The organization the library's coordinate opens with (`org.scala-lang`) | No |
| PHP | The authors the lock entry lists | No |
| Maven | The organization the artifact's POM names, or its developers when it names none; both inherited from parent POMs | Yes |
| Python | The maintainers PyPI lists, or the authors when it lists none | Yes |
| Ruby | The authors rubygems.org lists | Yes |
| Rust | The crates.io account that published the version | Yes |
| JavaScript | The author the package's manifest declares, or the npm account that published the version when it declares none | Yes |

What to keep in mind when reading them:

- **They are not all the same kind of fact.** A POM's organization is a
  name an entity goes by. A Go module path's owner, an sbt organization
  and a registry account are identifiers: they say who controls the name,
  not what that party is called.
- **Person or organization is mostly unknown.** Only Maven says which a
  supplier is. Go and sbt suppliers are written as organizations; the
  rest as persons, so `Pallets` or `Shopify` come out as persons.
- **Several suppliers, one field.** A package with several authors or
  maintainers has them all on its node. SPDX 2.3 holds one supplier per
  package and shows the first.
- **No source, no supplier.** A package whose metadata names nobody gets
  none; nothing is made up.
- **The root is not named.** Who supplies the software the document
  describes is for whoever writes the document to say, with
  `--supplier`, as the document's authors are with `--author`. Both take
  an entity written the way SPDX writes one:
  `"Organization: Example Inc (security@example.com)"` or
  `"Person: Jane Doe"`.

## Networking tiers

The `DecomposerOptions.Networking` field controls how much network access
decomposers are allowed. This is a top-level option that affects all
decomposers uniformly.

| Level | Value | Description |
|-------|-------|-------------|
| `NetworkEssential` | `0` (default) | Enables network calls essential for building the dependency tree plus lightweight metadata requests (deps.dev, checksum files, crates.io API). |
| `NetworkFull` | `1` | All of essential, plus downloading full artifacts for hash computation and zip archives for license classification. Prioritizes completeness over bandwidth. |
| `NetworkDisabled` | `-1` | No network calls. Only local data is used. Some decomposers will produce incomplete results (Go and Maven lose transitive dependencies) while others keep the whole graph and only lose what is fetched to enrich it (licenses, suppliers). |

### Per-decomposer networking behavior

| Call | disabled | essential | full |
|------|----------|-----------|------|
| **Go:** proxy .mod fetch (dependency graph) | skip | yes | yes |
| **Go:** deps.dev API (licenses, VCS) | skip | yes | yes |
| **Go:** proxy .zip download (license fallback) | skip | skip | yes |
| **Go binary:** build info read | works | works | works |
| **Go binary:** module-to-module edges from the local module cache | works | works | works |
| **Go binary:** everything else | as Go | as Go | as Go |
| **Rust binary:** record read, full graph | works | works | works |
| **Rust binary:** crates.io API (enrichment) | skip | yes | yes |
| **Maven:** direct dependencies, from `pom.xml` and the parent POMs beside it | works | works | works |
| **Maven:** POM fetch (transitive dependencies, licenses, suppliers) | skip | yes | yes |
| **Maven:** metadata fetch (snapshots, ranges) | skip | yes | yes |
| **Maven:** checksum files (.sha1, .sha256) | skip | yes | yes |
| **Maven:** artifact download (SHA-256/SHA-512) | skip | skip | yes |
| **JavaScript:** local parsing (lock files, manifests) | works | works | works |
| **JavaScript:** npm registry (suppliers, and licenses the lock lacks), for packages of the public registry only | skip | yes | yes |
| **PHP:** _(none -- fully offline, licenses included)_ | works | works | works |
| **Python:** local parsing (lockfiles, requirements) | works | works | works |
| **Ruby:** local parsing (Gemfile.lock) | works | works | works |
| **Ruby:** rubygems.org API (licenses, metadata) | skip | yes | yes |
| **Python:** PyPI JSON API (licenses, metadata) | skip | yes | yes |
| **Rust:** local parsing (Cargo.toml/lock) | works | works | works |
| **Rust:** crates.io API (enrichment), one request a second | skip | yes | yes |

## Dependency inclusion flags

By default, only production/compile dependencies are included in the
output. Three flags control the inclusion of additional dependency types:

| Flag | CLI | Default | Description |
|------|-----|---------|-------------|
| `IncludeDev` | `--include-dev` | `false` | Include development and test dependencies |
| `IncludeBuild` | `--include-build` | `false` | Include build tool dependencies |
| `IncludeOptional` | `--include-optional` | `false` | Include optional dependencies |

### Per-decomposer mapping

| Flag | Go | Maven | npm | PHP | Python | Ruby | Rust | sbt |
|------|-------|-------|-----|-----|--------|------|------|-----|
| `--include-dev` | _(no-op)_ | test-scoped deps | `devDependencies` (all lockfiles) | `require-dev` | dependency groups (PEP 735) | _(no-op)_ | `[dev-dependencies]` | `development` scope |
| `--include-build` | _(no-op)_ | `<build><plugins>` | _(no-op)_ | _(no-op)_ | _(no-op)_ | _(no-op)_ | `[build-dependencies]` | _(no-op)_ |
| `--include-optional` | _(no-op)_ | `<optional>true</optional>` | `optionalDependencies` | _(no-op)_ | extras | _(no-op)_ | _(no-op)_ | _(no-op)_ |

**Notes:**

- Go modules do not distinguish dependency types in `go.mod`, so all
  three flags are no-ops for the Go decomposer.
- Maven's scope transitivity rules still apply: a test-scoped dependency
  declared by one of your compile-scoped dependencies will never be
  included, even with `--include-dev`. The flag only affects dependencies
  declared directly in your own POM (or resolved at the current project
  level).
- npm's `peerDependencies` are not covered by these flags. A project's
  own peers are related to it as provided dependencies when installed,
  and an installed package's peers are followed like its other
  dependencies; see the [JavaScript page](npm.md#peer-dependencies).
- Maven's `provided` scope is not covered by these flags and remains
  a decomposer-specific option (`IncludeProvided`).
- Ruby's Gemfile is executable code, so group membership cannot be read
  statically: all three flags are no-ops and every declared gem is
  included. See the [Ruby page](ruby.md).
- Python resolves for one target environment (platform and interpreter
  version); see the [Python page](python.md) for the `--platform` and
  `--python-version` flags that pick it.
- Installed Python environments (site-packages) and installed Composer
  environments (vendor directories) are read by system decomposers that
  run in image and filesystem scans, beside the rpm, deb and apk
  readers. See the [Python](python.md) and [PHP](composer.md) pages.
- Go executables record the modules linked, with no dependency kinds, so
  the flags are no-ops for the [Go binary](gobinary.md) decomposer too.
- cargo-auditable records which crates were build dependencies, so
  `--include-build` works for the [Rust binary](rustbinary.md) decomposer;
  the other two flags are no-ops there.

## Per-decomposer docs

See the individual pages linked in the table above for implementation
details, data sources, and known limitations.

## Writing a new one

[HOWTO.md](HOWTO.md) explains how subjects, unpackers and decomposers fit
together and walks through implementing a source decomposer, a system
decomposer, an artifact decomposer, or a new unpacker.

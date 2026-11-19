# Maven Decomposer

**Location:** `source/maven/`

## How it works

1. Parses the local `pom.xml`.
2. Resolves the effective POM by walking the parent chain, processing
   BOM imports (`scope=import`, `type=pom`), and interpolating
   `${property}` placeholders. A parent is looked for in the source
   tree first, where a multi-module project keeps it: at the path its
   `relativePath` names, `../pom.xml` by default, and used when it is
   the artifact the POM names as its parent. Otherwise it is fetched
   from the repository. From a parent a POM inherits properties,
   dependency management, dependencies, licenses, the organization and
   the developers.
3. Builds the dependency tree via BFS, applying Maven's rules:
   - **Mediation.** The nearest definition of an artifact wins, and
     every dependent that requires it gets an edge to the version
     chosen, so a package can have several parents.
   - **Scope.** Transitivity is decided on the scope a dependency is
     declared with. An artifact reached through several paths takes the
     widest scope among them; one the project declares itself keeps its
     declared scope.
   - **Exclusions**, accumulated along each path.
   - **`dependencyManagement`.** For the project's own dependencies it
     fills in what a declaration leaves out. For transitive ones it is
     the project's decision: the managed version and scope replace what
     the dependency's POM states, and managed exclusions add to its own.
4. Fetches artifact checksums (`.sha1`, `.sha256`) from the repository
   in parallel. With `NetworkFull`, also downloads the actual
   artifacts and computes SHA-256/SHA-512 locally using the
   `github.com/carabiner-dev/hasher` library.
5. Resolves SNAPSHOT versions via the version-level
   `maven-metadata.xml` to find timestamped artifact filenames.
6. Converts the tree to a protobom NodeList using BFS edge ordering
   to guarantee parents are added before children.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | POM | `artifactId` |
| Version | POM / mediation | After range resolution and management |
| PURL | computed | `pkg:maven/{groupId}/{artifactId}@{version}[?type=...&classifier=...&repository_url=...]` |
| Download URL | computed | Full artifact URL using correct type/classifier |
| Hashes | `.sha1`/`.sha256` files | Fetched in parallel; optionally SHA-256/SHA-512 computed locally |
| License | dependency POM | Normalized to SPDX via `license.Normalize(name, url)` |
| Scope | POM | Maps to edge types: `dependsOn`, `devDependency`, `optionalDependency` |
| Supplier | dependency POM | The `<organization>`, as an organization with its URL, or the `<developers>` when there is none, each by name or id. Inherited from parent POMs. Needs networking; see [Suppliers](README.md#suppliers) |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `RepoURL` | `string` | `https://repo1.maven.org/maven2` | Maven repository URL |
| `Concurrency` | `int` | `10` | Parallel HTTP requests |
| `IncludeTest` | `bool` | `false` | Include test-scoped dependencies |
| `IncludeProvided` | `bool` | `false` | Include provided-scoped dependencies |
| `IncludeOptional` | `bool` | `false` | Include optional dependencies |
| `IncludeBuild` | `bool` | `false` | Include build plugins as dependencies |

Artifact download for SHA-256/SHA-512 computation is controlled by the
top-level `Networking` setting (`NetworkFull`).

With networking disabled there is no repository to read other POMs from,
and the graph holds what the source tree states: the project's direct
dependencies, with its own properties and dependency management and
those of the parent POMs beside it. Transitive dependencies, licenses,
hashes and suppliers need the network.

## Dependency types

| Common flag | Maven equivalent | What it includes |
|-------------|-----------------|------------------|
| `--include-dev` | `IncludeTest` | Dependencies with `<scope>test</scope>` declared in the project's own POM. Maven's transitivity rules still apply: test-scoped transitive deps from compile-scoped dependencies are never included. |
| `--include-build` | `IncludeBuild` | Plugins from `<build><plugins>` and `<build><pluginManagement>`. Only plugins with an explicit version are included. Plugins without a groupId default to `org.apache.maven.plugins`. Edge type: `buildDependency`. |
| `--include-optional` | `IncludeOptional` | Dependencies with `<optional>true</optional>`. Edge type: `optionalDependency`. |

The `provided` scope (`IncludeProvided`) is a decomposer-specific option
not mapped to any common flag.

## Generation context

`source`. The decomposer reads `pom.xml` as it stands in the source tree
and the POMs it leads to, before anything is built, so a document made
from its data is a source SBOM: CycloneDX lifecycle `pre-build`, SPDX 3
type `source`. See
[Generation context](README.md#generation-context).

## Strengths

- **Full POM resolution.** Handles parent chains, local and remote, BOM
  imports, property interpolation, and version ranges.
- **A graph, not a tree.** Every dependent of a mediated artifact is
  related to it, so the answer to "what depends on this" is complete.
- **Held to Maven itself.** A conformance test compares the resolved
  packages with `mvn dependency:tree` run in Docker.
- **License extraction and normalization.** Reads `<licenses>` from every
  dependency's POM and normalizes via the SPDX license list and
  CycloneDX alias mapping.
- **SNAPSHOT support.** Resolves timestamped snapshot versions from
  `maven-metadata.xml` so that artifact URLs and hashes point to the
  correct files.
- **Complete PURLs.** Includes `type`, `classifier`, and `repository_url`
  qualifiers when applicable.
- **Parallel I/O.** All POM, hash, and artifact fetches use the
  `khttp.Agent.GetGroup` parallel fetcher.

## Weaknesses

- **Network-heavy.** Resolving the full tree requires fetching the POM
  for every transitive dependency. Large dependency trees produce
  hundreds of HTTP requests.
- **Single repository.** Only one Maven repository URL is supported.
  Projects that pull from multiple repositories (Gradle-style) may
  have missing dependencies.
- **No Gradle support.** Only `pom.xml` is parsed; Gradle builds are not
  understood. sbt builds have a [decomposer of their own](sbt.md).
- **Sibling modules are not read.** Each `pom.xml` is a codebase of its
  own, and `<modules>` is not followed. A module depending on a sibling
  that was never published keeps it as a node with nothing under it.
- **Full hashing is expensive.** With `NetworkFull`, downloading
  every JAR to compute SHA-512 significantly increases runtime and
  bandwidth.

# Maven Decomposer

**Location:** `source/maven/`

## How it works

1. Parses the local `pom.xml`.
2. Resolves the effective POM by walking the parent chain, processing
   BOM imports (`scope=import`, `type=pom`), and interpolating
   `${property}` placeholders.
3. Builds the dependency tree via BFS, applying Maven's
   nearest-definition-wins mediation, scope transitivity rules,
   exclude directives, and `dependencyManagement` overrides.
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

## Dependency types

| Common flag | Maven equivalent | What it includes |
|-------------|-----------------|------------------|
| `--include-dev` | `IncludeTest` | Dependencies with `<scope>test</scope>` declared in the project's own POM. Maven's transitivity rules still apply: test-scoped transitive deps from compile-scoped dependencies are never included. |
| `--include-build` | `IncludeBuild` | Plugins from `<build><plugins>` and `<build><pluginManagement>`. Only plugins with an explicit version are included. Plugins without a groupId default to `org.apache.maven.plugins`. Edge type: `buildDependency`. |
| `--include-optional` | `IncludeOptional` | Dependencies with `<optional>true</optional>`. Edge type: `optionalDependency`. |

The `provided` scope (`IncludeProvided`) is a decomposer-specific option
not mapped to any common flag.

## Strengths

- **Full POM resolution.** Handles parent chains, BOM imports, property
  interpolation, replace directives, and version ranges.
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
- **No Gradle/SBT support.** Only `pom.xml` is parsed. Gradle wrapper
  or SBT build files are not understood.
- **Full hashing is expensive.** With `NetworkFull`, downloading
  every JAR to compute SHA-512 significantly increases runtime and
  bandwidth.

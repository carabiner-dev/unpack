# Gradle Decomposer

**Location:** `source/gradle/`

Reads projects built with [Gradle](https://gradle.org/), Java, Kotlin
and Android ones above all, from the lockfiles Gradle writes when
[dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html)
is on, with the checksums of its
[dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html)
when the build has them. Gradle is not run and extraction is offline.

A build that does not lock its dependencies is not found. What it
depends on is in its build scripts, `build.gradle` or
`build.gradle.kts`, which are Groovy and Kotlin programs.

## How it works

1. `FindCodeBases` finds the directories holding a `gradle.lockfile` or
   a `buildscript-gradle.lockfile`. Every project of a build has its
   own, beside its build file, so each project with one is a codebase.
2. `gradle.lockfile` is read: a line a module version, with the
   configurations that have it.

   ```
   com.google.guava:guava:33.2.0-jre=runtimeClasspath,testRuntimeClasspath
   ```

3. Each module is a dependency of the project, of a kind read off its
   configurations; see below.
4. `buildscript-gradle.lockfile`, the classpath of the build script, is
   read the same way: its modules are the plugins of the build and what
   they require, and are build dependencies.
5. `gradle/verification-metadata.xml` is looked for at the project and
   then above it, up to the root of the git repository, as a project is
   below the root of its build. A module it has checksums for takes
   them.

## What a module is to the project

A lockfile says which configurations a module is in, and the names of
configurations are how Gradle's plugins say what a classpath is for. The
Java plugin has `compileClasspath`, `runtimeClasspath` and
`annotationProcessor`, and the same for the tests with a `test` prefix;
the plugins built on it, Android's among them, prefix those with a
source set or a variant (`debugRuntimeClasspath`,
`releaseUnitTestCompileClasspath`).

The configurations outside the tests decide:

| The module is in | It is | Edge |
|------------------|-------|------|
| a `…RuntimeClasspath` | Shipped with the project | `dependsOn` |
| a `…CompileClasspath` and no runtime one | Compiled against, and provided by something else when the project runs (`compileOnly`) | `providedDependency` |
| only `…AnnotationProcessor` | Run in the compiler | `buildDependency` |
| only test configurations | The tests' own | `devDependency` |
| a configuration with another name | Taken as shipped | `dependsOn` |

The last row is deliberate. A configuration a build defines itself, or
one of a plugin's own (`checkstyle`, `jacocoAgent`), has a name that
says nothing here, and a module is left out of the runtime only on the
word of a name that says so. A code quality tool locked that way is
listed as a dependency. Every configuration is on the node, in
`gradle:configuration` properties, for a reader who knows the build.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | lockfile | The module's name, as the Maven decomposer names artifacts |
| Version | lockfile | |
| PURL | computed | `pkg:maven/{group}/{name}@{version}` |
| Hashes | verification metadata | Of the module's library, its `.jar` or `.aar`: SHA-256, SHA-512, SHA-1 or MD5, as the build states them |
| `gradle:configuration` | lockfile | Once for each configuration |
| `gradle:buildscript` | | `true` for a module of the build script's classpath |
| `gradle:verified-file` | verification metadata | The file the hashes are of |

There is no license and no supplier: neither file states them.

### Hashes

Verification metadata is the build's own record of what its dependencies
hash to, and Gradle refuses a file that does not match. A module has an
entry for each of its files that is verified, its POM and its Gradle
metadata as well as its library; the node takes the library's, which is
what the project is built from.

Not every module has them. A build may verify by signature alone (a
`<pgp>` entry is a key and no checksum), trust a group outright, or not
verify at all. Those nodes have no hash.

## The root

| Field | Source |
|-------|--------|
| Name | The directory name |
| Version | The version unpack reads from git |
| PURL | `pkg:generic/{name}@{version}` |
| License | The project's license file; see [The codebase's own license](README.md#the-codebases-own-license) |

The project's own coordinates are in its build script and are not read.

## Dependency types

| Common flag | What it includes |
|-------------|------------------|
| _(none)_ | Modules shipped with the project and modules it is compiled against |
| `--include-dev` | Modules only the tests have |
| `--include-build` | Annotation processors, and the build script's classpath |
| `--include-optional` | _(no-op)_ |

## Generation context

`source`. The lockfiles are read as they stand in the source tree, so a
document made from this data is a source SBOM: CycloneDX lifecycle
`pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Networking

None.

## Strengths

- **Exact versions**, from Gradle's own record of what it resolved.
- **Real file hashes** where the build verifies its dependencies.
- **Runtime, compile-only, test and build dependencies are told apart**,
  for the configurations whose names say.
- **Plugins are in the inventory**, from the build script's lockfile.
- **Offline**, with nothing to install.

## Weaknesses

- **Only builds that lock.** Dependency locking is opt-in and most
  builds do not use it. Version catalogs (`gradle/libs.versions.toml`)
  and build scripts are not read.
- **The graph is flat.** A lockfile has no edges: which module requires
  which is not in it, nor which of them the project declares itself.
- **No licenses or suppliers.** They are in each module's POM, which is
  on a repository; the Maven decomposer fetches those, and this one does
  not yet.
- **Each project of a build is its own codebase.** A build of twenty
  projects is twenty, and a library they share is in each.
- **Configurations of other names are taken as shipped**; see above.
- **A lockfile under another name** (`lockFile` set in the build) or in
  the older one-file-a-configuration layout is not found.

# sbt Decomposer

**Location:** `source/sbt/`

Reads the dependencies of [sbt](https://www.scala-sbt.org/) builds. An sbt
build is Scala code: what it depends on is only known once sbt has loaded
the build and resolved it, so unpack does not read `build.sbt`. It reads
the GitHub dependency snapshot that
[sbt-dependency-submission](https://github.com/scalacenter/sbt-dependency-submission)
writes from sbt's own resolution, the document it submits to GitHub's
dependency graph.

The decomposer is off by default. It only runs when pointed at a snapshot:

```bash
unpack extract --sbt-snapshot dependency-snapshot.json sbt:.
```

## Getting a snapshot

The snapshot is written by the plugin's `githubGenerateSnapshot` command,
to a temporary file (`dependency-snapshot-*.json` in the JVM's temporary
directory) whose path it reports in the `snapshot-json-path` step output.
There is no default location to look for.

The `scalacenter/sbt-dependency-submission` action generates the snapshot
and submits it to GitHub. To generate it without submitting, add the plugin
to the build and run the command yourself, in a GitHub Actions job (the
plugin reads the commit and run from the job's environment):

```bash
echo 'addSbtPlugin("ch.epfl.scala" % "sbt-github-dependency-submission" % "3.2.3")' \
  > project/github-dependency-submission.sbt
sbt 'githubGenerateSnapshot {"ignoredModules":[],"ignoredConfigs":[]}'
# the path is in $GITHUB_OUTPUT as snapshot-json-path
```

## How it works

1. `FindCodeBases` locates the build the snapshot describes. A tree can
   hold many sbt builds (scripted test fixtures carry their own
   `build.sbt`); the manifests record the build file's path relative to
   the workspace, and of the directories holding a `build.sbt` at that
   path, the shallowest is the build.
2. The root node is the build: the repository at the commit the snapshot
   was taken. See [the root node](#the-root-node).
3. Every manifest is a module of the build — one per project and Scala
   version it cross-builds for, named `organization:name:revision` — and
   becomes a node the root depends on (`dependsOn`).
4. From each module, the walk follows its direct dependencies and, from
   them, the callers sbt recorded. Modules sbt resolved but the walk
   cannot reach (their callers were evicted) hang from the module, so
   nothing resolved drops out of the inventory.
5. Nodes are shared by purl across manifests: a library many modules use
   is one node, and a module of the build another module depends on is
   the node its manifest describes, which links the modules into their
   real graph.

## The root node

| Field | Source |
|-------|--------|
| Name | The repository name when the snapshot was generated on github.com, the directory name otherwise |
| Version | The version unpack reads from git, else the tag of the snapshot's ref (`refs/tags/3.9.0` → `3.9.0`) |
| PURL | `pkg:github/{owner}/{repo}@{version}` on github.com, `pkg:generic/{name}@{version}` otherwise |
| VCS reference | The commit, as a SHA-1 hash and in the locator (`git+https://github.com/{owner}/{repo}@{commit}`) |

The repository is read from the run URL of the snapshot's job. When
unpack reads the commit from a git checkout and the snapshot was taken at
another commit, extraction fails: the snapshot describes another build.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | purl | The artifact id, cross-version suffix included (`scala3-library_3`) |
| Version | purl | |
| PURL | snapshot | `pkg:maven/{org}/{name}@{version}`, with `?packaging=` for classifiers |

## Dependency types

sbt resolves every configuration of a project (`compile`, `test`, the
tool configurations); the plugin records each module under the scope of
the first configuration it was found in: `runtime` for the runtime
configurations, `development` for the rest.

| Common flag | sbt equivalent | What it includes |
|-------------|----------------|------------------|
| `--include-dev` | `development` scope | Test and tool configurations, as `devDependency` edges |
| `--include-build` | _(no-op)_ | |
| `--include-optional` | _(no-op)_ | |

## Networking

None. sbt already resolved the build; reading the snapshot is offline.

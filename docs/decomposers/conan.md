# Conan (C and C++) Decomposer

**Location:** `source/conan/`

Reads C and C++ projects whose dependencies are managed with
[Conan](https://conan.io/), from the lockfile Conan writes
(`conan.lock`) and the declarative manifest (`conanfile.txt`). Conan is
not run and extraction is offline.

Lockfiles of both Conan 2 and Conan 1 are read; they are two different
documents, and the older one holds more. The other form of a recipe,
`conanfile.py`, is a Python program and is not read: a project that has
one and no lockfile is not found.

## How it works

1. `FindCodeBases` finds the directories holding a `conan.lock` or a
   `conanfile.txt`.
2. With a Conan 2 lockfile, the packages are the lockfile's: every reference of
   its lists, at the version and recipe revision it pins.

   | List | What it holds | Edge |
   |------|---------------|------|
   | `requires` | What the project, and its tests, are built from | `dependsOn` |
   | `build_requires` | What runs on the build machine: tools | `buildDependency` |
   | `python_requires` | What the recipe itself is written with | `buildDependency` |
   | `config_requires` | Packages Conan's configuration is installed from | `buildDependency` |

   The lists are sorted newest first. A lockfile may hold several
   revisions of one version, after a merge; the first is kept.
3. The manifest, when there is one, says what a package is for where the
   lockfile cannot: a lockfile lists test requirements with the rest of
   `requires`, as both are built for the same machine, so a package the
   manifest names under `[test_requires]` is a `devDependency`, and one
   under `[tool_requires]` a `buildDependency`.
4. Without a lockfile, the packages are the manifest's: `[requires]`,
   `[tool_requires]` and `[test_requires]`, each at the version it
   states. A requirement that asks for a range (`zlib/[>=1.2 <2]`) gets
   no version; the range is on the node. This is what the project asks
   for and not what was resolved: none of what those packages require in
   turn is there.

The other sections of a manifest, `[generators]`, `[options]` and
`[layout]`, configure the build and name no package. The `overrides` of
a lockfile name none of their own either.

### Conan 1 lockfiles

A Conan 1 lockfile (a `graph_lock` of nodes, format version `0.4`) is
the dependency graph itself: each node is a package and lists the nodes
it requires. So the graph is not flat here. It is walked from the node
the lockfile was made for, the one no other requires, and every edge is
the lockfile's:

```
legacy
  ├ dependsOn ─▶ applib/1.0@acme/stable
  │                 └ dependsOn ─▶ zlib/1.2.11
  └ dependsOn ─▶ openssl/1.1.1k
                    └ dependsOn ─▶ zlib/1.2.11
```

- `requires` edges are `dependsOn`, `build_requires` edges
  `buildDependency`, and what a build requirement requires is only there
  with `--include-build`.
- A node's `python_requires` are `buildDependency` edges from it.
- The manifest marks the project's own test and tool requirements, as
  for Conan 2.
- A package the graph holds twice, built for the target and for the
  build machine, is one node.
- Each node carries the package id the lockfile pins, and the package
  revision when revisions were in use.

Conan 1 called the format experimental and changed it between releases.
A lockfile whose graph cannot be made out, one of an older shape or a
lock bundle, is left aside with a warning, and the project is read from
its manifest as if it had no lockfile.

### References

A package is named as Conan writes it:

```
name/version[@user[/channel]][#recipe revision[%timestamp]]
```

The user and channel, when there are any, tell a package of an
organization's own from the one of the same name on Conan Center.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | lockfile / manifest | |
| Version | lockfile / manifest | Exact from a lockfile; from a manifest only when it pins one |
| PURL | computed | `pkg:conan/{name}@{version}` with the qualifiers the type defines: `rrev`, `user`, `channel` |
| `conan:recipe-revision` | lockfile | See below |
| `conan:package-id`, `conan:package-revision` | lockfile | In a Conan 1 lockfile, and in a Conan 2 one made to lock binaries; one of each per binary |
| `conan:version-range` | manifest | The range asked for, on a node with no version |

There is no license, no supplier and no download location: neither file
states them.

### No hashes

The recipe revision is a hash, of the recipe: the `conanfile.py` and the
files exported with it that tell Conan how to build the package. It
changes when the recipe does and says nothing of the library's sources
or of the binaries built from them, so it is a property and a purl
qualifier and not one of the node's hashes. A Conan lockfile pins no
hash of content.

## The root

| Field | Source |
|-------|--------|
| Name | The directory name: neither file names the project |
| Version | The version unpack reads from git |
| PURL | `pkg:generic/{name}@{version}` |
| License | The project's license file; see [The codebase's own license](README.md#the-codebases-own-license) |

## Dependency types

| Common flag | Conan equivalent | What it includes |
|-------------|------------------|------------------|
| `--include-dev` | `[test_requires]` | Packages the manifest names for the tests. Without a manifest a lockfile does not tell them from the rest, and they are plain dependencies |
| `--include-build` | `build_requires`, `python_requires`, `config_requires`, `[tool_requires]` | Tools and recipe tooling |
| `--include-optional` | _(no-op)_ | |

## Generation context

`source`. The lockfile and manifest are read as they stand in the source
tree, so a document made from this data is a source SBOM: CycloneDX
lifecycle `pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Networking

None.

## Strengths

- **Exact versions**, which reading a C++ build system cannot give: the
  lockfile is Conan's own record of what it resolved.
- **A real graph from Conan 1 lockfiles**, direct and transitive told
  apart.
- **Identifiers tools know.** `pkg:conan` purls, with the recipe
  revision.
- **Private packages are told apart** by their user and channel.
- **Offline**, with nothing to install.

## Weaknesses

- **The graph is flat for Conan 2.** A Conan 2 lockfile is lists of
  references with no edges: which package requires which is not in it,
  nor which of them the project asks for directly. Every package hangs
  from the root. A Conan 1 lockfile has the edges.
- **No hashes, licenses or suppliers.** See above.
- **`conanfile.py` is not read.** Most recipes are written in Python,
  and many projects commit no lockfile; those are not found. With a
  lockfile and a Python recipe, test requirements are not told from the
  rest.
- **Conan 1 lockfiles are found by one name.** `conan.lock` is the
  default, and Conan 1 projects often wrote theirs elsewhere
  (`locks/app.lock`); those are not found.
- **A lockfile can hold more than a build uses.** Lockfiles are merged
  and added to by hand; everything listed is reported.
- **The profile is not known.** Which settings and options the packages
  were resolved for is not in the lockfile, so a package required on one
  platform only is listed for all.

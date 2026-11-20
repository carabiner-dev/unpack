# CMake (C and C++) Decomposer

**Location:** `source/cmake/`

Reads what a C or C++ project built with [CMake](https://cmake.org/)
says it depends on, from its CMake files alone. CMake is not run and
nothing needs to be installed.

The decomposer is off by default and runs when asked for:

```bash
unpack extract --enable cmake /path/to/project
unpack ls --enable cmake /path/to/project
```

A library caller sets `dependencies.Options.Decomposers["cmake"] = true`.

Read this page before trusting the output. A CMake project has no
lockfile and no manifest: it is a program that asks the machine it is
configured on for the packages it wants, and which of those questions it
asks depends on options and on what is installed. The files hold the
questions. So this decomposer reports **what the project may depend on**,
labelled with how sure each one is, and not what one build of it found.
There are no versions for packages looked up on the machine.

## How it works

1. `FindCodeBases` finds the directories whose `CMakeLists.txt` declares
   a `project()`, the outermost of them: a project has a
   `CMakeLists.txt` in most of its directories.
2. Every `CMakeLists.txt` and `*.cmake` file under it is parsed. A
   directory below the root that declares a project of its own, vendored
   code or an example, is left out with what is under it, and so is a
   build tree (a directory holding `CMakeCache.txt`).
3. The plain definitions are collected: `option()` defaults, and
   variables `set()` to one literal value. A variable set to different
   values in different places has none.
4. The commands that ask for a package are read:

   | Command | What is read |
   |---------|--------------|
   | `find_package(Name [version] [EXACT] [REQUIRED])` | The name, the version asked for, whether the build stops without it |
   | `pkg_check_modules(PREFIX [REQUIRED] module>=version ...)`, `pkg_search_module` | Each pkg-config module and its version range; of a search, the first |
   | `FetchContent_Declare(name ...)`, `ExternalProject_Add(name ...)` | `GIT_REPOSITORY`, `GIT_TAG`, `URL`, `URL_HASH` |

5. Each command is given a status from the `if()` blocks around it and
   the `add_subdirectory()` that leads to its directory; see below.
6. A package asked for in several places is one node, with the surest of
   its statuses.

`find_package(PkgConfig)` and `find_package(Threads)` name no package
and are dropped: both are modules CMake ships, for the pkg-config tool
and the system's thread library.

Only commands CMake defines are read. A project's own conventions for
recording its dependencies, a copyright file or the macros of an SBOM
module, are not: they would have to be learned one project at a time.

### The project's own find modules

A `Find<Name>.cmake` in the project is how the project looks `Name` up.
Two things are read from it, and its commands are not dependencies of
their own:

- The pkg-config modules it checks, which give the package its
  pkg-config name and a version range (`FindROHC.cmake` checking
  `rohc>=2.3.1`).
- A `find_package()` of another name: the module only dresses up a
  package that goes by that name, and the dependency is reported as it.
  `find_package(YAMLCPP)` with a `FindYAMLCPP.cmake` that looks for
  `yaml-cpp` is a dependency on `yaml-cpp`.

## Status

Every dependency node has a `cmake:status` property:

| Status | Meaning | Example |
|--------|---------|---------|
| `required` | The default configuration does not configure without it | `find_package(ZLIB REQUIRED)` at the top level; anything fetched |
| `optional` | The default configuration asks for it and goes on without | `find_package(Snappy)` |
| `conditional` | Behind a condition the files do not settle | Inside `if(WIN32)` or `if(FOO_FOUND)` |
| `disabled` | Behind an option that is off by default | Inside `if(ENABLE_GPU)` with `option(ENABLE_GPU ... OFF)` |

Conditions are evaluated as far as the files settle them: constants,
options at their default, variables set to one literal value, joined by
`NOT`, `AND` and `OR`. Anything else is unknown: comparisons, `DEFINED`,
parentheses, the platform, the result of another lookup. A directory is
entered when the `add_subdirectory()` naming it runs.

"Default configuration" is the point: a build given `-DENABLE_GPU=ON`
has what is reported here as `disabled`.

## Dependency types

| Common flag | What it includes |
|-------------|------------------|
| _(none)_ | What the default configuration asks for: status `required` as `dependsOn`, and `optional` and `conditional` as `optionalDependency` |
| `--include-optional` | Those with status `disabled`, as `optionalDependency` |
| `--include-dev` | _(no-op)_ |
| `--include-build` | _(no-op)_ |

The files do not say what a package is for, so test frameworks and the
tools the build runs are listed like everything else: `GTest` asked for
by the tests and `Python3` asked for by a code generator are
dependencies of the project here. Telling them apart would take a list
of names, and a guess is not what this decomposer reports.

**Optional dependencies are in without the flag**, unlike in the other
decomposers. To a package manager an optional dependency is one that is
not installed unless asked for, and leaving it out matches what is
installed. A `find_package()` with no `REQUIRED` means "use it when it
is there", and on a machine set up to build the project it is: OpenSSL,
FFTW and the like are optional to CMake and in nearly every build. A
project can require as few as three packages and link thirty, so the
default shows what the default configuration asks for, each marked with
its status, and keeps back only what an option turns off.

`conditional` dependencies are shown too, and can exclude each other:
what is behind `if(WIN32)` and what is behind its `else()` are both
listed, though no build has both.

## Data produced

### The root

| Field | Source |
|-------|--------|
| Name | `project()`, else the directory name |
| Version | The version unpack reads from git, else `project(... VERSION x)` |
| PURL | `pkg:generic/{name}@{version}` |
| License | The project's license file; see [The codebase's own license](README.md#the-codebases-own-license) |

### Per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | the command | As the project asks for it: `OpenSSL`, `libdpdk`. Not normalized to any registry's name |
| Version | `GIT_TAG`, `find_package(... EXACT)`, pkg-config `=` | Only when the project pins one. A tag in a variable is resolved when the files set it |
| PURL | computed | `pkg:github/{owner}/{repo}@{tag}` (or `gitlab`, `bitbucket`) for a fetched repository; `pkg:generic/{name}` otherwise |
| Repository | `GIT_REPOSITORY` | `ExternalReference_VCS` |
| Download URL, hash | `URL`, `URL_HASH` | Fetched archives only |
| `cmake:status` | see above | |
| `cmake:version-constraint` | the command or the find module | The range accepted: `>=2.3.1`, `3.0...<4` |
| `cmake:command` | | Each command that asks for it |
| `cmake:pkg-config` | | Each pkg-config module it is looked up as |
| `cmake:declared` | | Each place it is asked for, as `file:line` |

There is no license and no supplier for dependencies: the files state
neither. Properties are written to CycloneDX documents only.

## Generation context

`source`. The CMake files are read as they stand in the source tree, so
a document made from this data is a source SBOM: CycloneDX lifecycle
`pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Networking

None.

## Strengths

- **Works on a bare checkout.** No CMake, no compiler, no dependencies
  installed.
- **Says how sure it is.** Status and the place of every request are on
  the node, so a reader can check any line of the inventory against the
  file it came from.
- **Fetched dependencies are exact.** Repository and tag, or URL and
  hash, as the project pins them.

## Weaknesses

- **No versions for looked-up packages.** The version is whatever the
  build machine has. A range is reported when the project states one.
- **The graph is flat.** What a dependency depends on is not in the
  project's files.
- **Vendored code is not seen.** Sources copied into the tree, header
  only libraries above all, are built with no command naming them. A
  subdirectory with a `project()` of its own is skipped, not reported.
- **Not every lookup is a `find_package`.** `find_library(dw)` and
  `find_path()` look for libraries too and are not read: a bare library
  name is not a package name. `CPMAddPackage`, Conan and vcpkg
  integration are not read either.
- **Names are the project's.** `OpenSSL`, `openssl` and `libssl` are
  three spellings of a dependency depending on the command used, and a
  `pkg:generic` purl matches no vulnerability database.
- **Conditions are approximated.** A dependency behind an unreadable
  condition is `conditional` whichever way it goes; functions and macros
  are taken as called; `include()` is not followed, every `*.cmake` file
  is read as if included; options changed by a preset or a toolchain
  file are not known.
- **Tests and tools are not told apart.** What only the tests or the
  build use is listed with what ships.

For an exact inventory of one build, generate an SBOM from the build
itself and read it with `unpack sbom`, or stitch it over this one with
`--add-sbom`.

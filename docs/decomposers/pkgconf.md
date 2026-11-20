# pkg-config Decomposer

**Location:** `source/pkgconf/`

Reads the [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
files a C or C++ project ships in its source tree: the `.pc` files, and
the `.pc.in` templates a build system fills in before installing them.
Such a file is the project describing a package it installs, and what a
user of that package needs with it.

The fields read, and what each becomes, follow
[pkgconf](https://github.com/pkgconf/pkgconf)'s own SBOM tools,
`spdxtool` and `bomtool`. pkgconf is not run: the files are parsed in Go,
in the format its `pc(5)` manual page specifies.

The decomposer is off by default and runs when asked for:

```bash
unpack extract --enable pkgconf /path/to/project
unpack ls --enable pkgconf /path/to/project
```

It is off because pkg-config files turn up in projects of every
language (a Rust or Go library with a C interface ships one), and a
repository that had one codebase would have two.

## What it reads, and what it does not

`spdxtool` is given the names of packages and resolves them, and what
they require in turn, against the pkg-config files **installed on the
machine**, which hold real versions. This decomposer reads the files in
a **source tree**, so:

- The packages are the project's own, the ones its files describe.
- What they require is known **by name**, with the range of versions
  the requirement states. The required package's own file is on the
  machine that builds the project, not in its source, so it has no
  version here and nothing it requires in turn is known.
- A template's values are often placeholders (`Version: @VERSION@`),
  and those are not known either.

Pointed at a directory of installed files (`/usr/lib64/pkgconfig`), it
reads them all the same, each with its real version; that is not what it
is for, and the result is one document with a root for every file.

## How it works

1. `FindCodeBases` finds every directory holding a pkg-config file: a
   `.pc` or `.pc.in` file that is one by pkgconf's own test, which is
   that it declares a `Name`, a `Description` and a `Version`. Each such
   directory is a codebase.
2. Every file of the directory is parsed: comments, variables,
   properties, a line carried on by a trailing backslash. Variables of
   the file are expanded (`Version: ${version}`). A package there both
   as a file and as its template, in a build tree, is read from the
   file.
3. Each file is a **root** of the graph: a package the project
   installs, known by the name of its file (`libssl.pc` is `libssl`),
   which is the name others require it by.
4. Each entry of its dependency lists is a `dependsOn` edge to a package
   known by name. When that name is another file of the directory, the
   edge goes to that package as its file describes it.

| Property of the file | What it becomes |
|----------------------|-----------------|
| file name | Name of the package |
| `Name` | `pkgconf:name` property, when it is not the file's name |
| `Version` | Version; the version unpack reads from git wins |
| `Description` | Description |
| `URL` | Home page |
| `Source` | Download location |
| `Maintainer` | Supplier: a name with an email or a website |
| `Copyright` | Copyright text, one statement a line |
| `License` | License; several lines are several licenses, meant joined by `AND` |
| `License.file` | `pkgconf:license-file` property |
| `Requires`, `Requires.private`, `Requires.internal`, `Requires.shared` | `dependsOn` edges |

`License`, `Maintainer`, `Source`, `Copyright` and `License.file` are
pkgconf's additions to the format, made for SBOMs. Few files have them
yet: none of the 111 installed on the machine this was developed on.
Where a file states no license, the project's license file is read
instead; see [The codebase's own license](README.md#the-codebases-own-license).

`Conflicts`, `Provides` and the compiler and linker flags are not part
of the graph. A requirement on `pkgconf` itself, which a file states to
say which pkgconf it needs, names the tool and is dropped.

### Files that are something else

The suffix does not make a pkg-config file. Other things are called
`.pc`, the sources of Oracle's Pro*C among them. pkgconf refuses a file
that lacks a `Name`, a `Description` or a `Version`, and the same test
is applied here: a file lacking one is left out, and a directory with no
file that passes is no codebase. The values may be placeholders; it is
the properties that have to be there.

What the test cannot tell is whose a real pkg-config file is. One in a
test fixture, or in a library copied into the tree, is a pkg-config file
like the project's own, and its directory is a codebase. `--ignore`
leaves such directories out.

### Every list is a dependency

`spdxtool` writes `Requires` and `Requires.private` alike as
dependencies, and so does this decomposer, for all four lists. They are
not the same thing to a build, though: what is under `Requires.private`
or `Requires.internal` is only linked into a static build, and what is
under `Requires.shared` only into a shared one. So each required package
says through which list it is required, in a `pkgconf:requires`
property, once for each.

### Placeholders

A value holding a placeholder (`@VERSION@`, as autoconf and CMake write
them) or a variable the file does not define is not known from the
source. It is left out, and the property is named in a
`pkgconf:unresolved` property of the package. In a dependency list the
settled entries are still read: `Requires: zlib @EXTRA_REQUIRES@` is a
requirement on `zlib`.

## Data produced per required package

| Field | Notes |
|-------|-------|
| Name | As the file requires it |
| Version | None: see above |
| PURL | `pkg:generic/{name}` |
| `pkgconf:requires` | The list or lists it is required through |
| `pkgconf:version-constraint` | The versions that will do, as written: `>= 1.2.11` |

## Dependency types

The inclusion flags are no-ops: a pkg-config file does not tell test or
build dependencies apart.

## Generation context

`source`. The files are read as they stand in the source tree. pkgconf's
own tools label their SBOMs `build`, and rightly: they read the files a
build installed. See [Generation context](README.md#generation-context).

## Networking

None.

## Conformance

The parser is held to pkgconf itself: for every pkg-config file
installed on the machine, the version and the `Requires` and
`Requires.private` lists it reads must be the ones `pkgconf` prints. The
test needs pkgconf and does not run in short mode.

## Strengths

- **The project's own statement.** A pkg-config file is written by the
  project to be read by a tool, in a specified format.
- **Works for any build system.** Autotools, CMake and hand-written
  Makefiles install pkg-config files alike.
- **Says what a user of the library needs**, which is the question an
  SBOM of a library answers.

## Weaknesses

- **No versions for what is required**, and none for the project's own
  packages when the file is a template.
- **Only what the file states.** A library's pkg-config file lists what
  its users need, which is less than what it is built from: a
  dependency linked statically and hidden, a build tool or a test
  framework is not in it.
- **Generated files are not there.** Meson and many CMake projects
  write their pkg-config files at build time from no template, and a
  source tree of theirs has none.
- **Names are pkg-config's.** `pkg:generic` purls match no
  vulnerability database, and one upstream project is often several
  packages (`libssl`, `libcrypto`, `openssl`).
- **Several files are several roots**, and a document with several
  roots cannot be written as CycloneDX today; SPDX can.

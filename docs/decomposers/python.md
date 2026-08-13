# Python Decomposer

**Location:** `source/python/`

Reads Python dependency data from four places: `uv.lock`, `poetry.lock`,
`requirements.txt`, and the `*.dist-info` directories of an installed
environment. Extraction needs no Python interpreter, and no network except
for license enrichment where noted.

A codebase holding several of these is read from the best one:
**`uv.lock` over `poetry.lock` over `requirements.txt`** — a requirements
file is usually exported from a lock, so the lock is the one kept current.
All package names are normalized (PEP 503) everywhere: `Flask`, `flask`
and `FLASK` are one project.

## How each source is read

### uv.lock

The lock is self-contained: versions, edges, environment markers and
artifact hashes are all resolved in it, and the manifest is not read. A
lock resolves every environment the project supports at once; an
extraction reads it for one, so one package appears at one version. Edges
keep or lose their place by their markers (PEP 508), and a package whose
resolution forked over the environment space contributes the entry the
edges select. Workspaces yield one root per member; git dependencies keep
their resolved commit.

Every registry node is hashed with the SHA-256 of the artifact the target
environment would install: the most specific compatible wheel by its
filename tags, installer-style, sdist as fallback. That is the file PyPI
attestations (PEP 740) bind to.

### poetry.lock

Read together with `pyproject.toml`, which carries what the lock does
not: the project's identity and its direct dependencies (both the
standard `[project]` table and the legacy `[tool.poetry]` one). Both lock
schemas are supported — 2.0 (Poetry 1.x) and 2.1 (Poetry 2.x). Each
dependency group is walked from its own declared directs, which derives
group membership on a 2.0 lock, where it is not recorded, and matches a
2.1 lock's stamps without trusting them. Poetry states membership in a
root extra as an `extra ==` marker on the extra's packages; enabling
extras enables them in the environment the markers evaluate against.
Hashes are wheel-selected from the lock's file lists; the lock names
artifacts by filename only, so nodes carry no download URL.

### requirements.txt

Read for what each line actually says. A compiled file (`pip-compile`,
`uv pip compile`) is as good as a lock, and its `# via` annotations
record which requirement pulled in which, so the tree is rebuilt from
them. A hand-written file declares constraints: the root borrows the
directory's name, since the format names no project, an entry without an
exact pin becomes a node without a version, and nothing is invented.
Includes (`-r`) are followed; editables and installer options are
skipped. A lone `--hash` is recorded; a compiled file's hash list names
every artifact of a package without saying which is which, so none is.

### Installed environments

The `*.dist-info` directories an installer writes into site-packages are
read by the **system decomposer** (`system/python/`), which runs in image
and filesystem scans beside the rpm, deb and apk readers: a container
image scan reports `pkg:pypi` packages next to the OS inventory. Unlike
those flat inventories, the result is a graph: installed metadata
declares dependencies, and a declaration whose target is installed is an
edge — an extra-gated one an `optionalDependency`. Roots come from the
REQUESTED marker (PEP 376) when it tells packages apart, and from the
graph's shape when it does not. Packages installed from a repository
carry their provenance down to the commit (PEP 610), and licenses need
no network at all: the metadata ships with the install.

## Targeting an environment

The graph is platform-conditional in Python, so the extraction resolves
for one concrete environment:

| Setting | CLI | Default |
|---------|-----|---------|
| Platform | `--platform os[/arch]` | the platform unpack runs on |
| Python version | `--python-version` | uv: the newest version the lock's own resolution forks mention, falling back to the floor of `requires-python`; poetry: the floor of the lock's python constraint |

The defaults describe what installing the project today, on this
machine, would get. The version default deliberately needs no Python
interpreter on the machine running unpack.

```bash
# What does this project install on an ARM Linux box running Python 3.10?
unpack extract --platform linux/arm64 --python-version 3.10 .
```

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | lockfile / METADATA | PEP 503 normalized |
| Version | lockfile / METADATA | The version the target environment resolves to; absent for unpinned requirements |
| PURL | computed | `pkg:pypi/{name}@{version}`, version-less when none is known |
| Download URL | lockfile | uv: the selected artifact's URL; git sources: the repository URL with its commit |
| Hash (SHA-256) | lockfile | The selected artifact's hash — the file PyPI attestations (PEP 740) bind to |
| Repository | lockfile / metadata / PyPI API | `ExternalReference_VCS`; for git dependencies includes the resolved commit |
| License | PyPI API / METADATA | See below; installed environments read it offline |
| Description | PyPI API / METADATA | The package summary |
| Homepage | PyPI API / METADATA | Set as `UrlHome` |
| Documentation | PyPI API / METADATA | `ExternalReference_DOCUMENTATION` |
| Installer | INSTALLER | Installed environments only, a `python:installer` property |

### Licenses

Lockfiles carry no license data at all, so lockfile extractions only
have licenses with networking enabled; installed environments read them
offline from the same fields in METADATA. Both use one triage, best
first:

1. A declared SPDX expression (PEP 639), used as is.
2. The free-text `license` field, normalized through the shared license
   catalog. Old packages stuff whole license texts into this field, so
   values that do not look like a short name are ignored.
3. Trove classifiers, only when the catalog recognizes the name:
   `License :: OSI Approved :: Apache Software License` does not say
   which Apache version, so unrecognized classifiers are dropped rather
   than guessed at.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `Platform` | `string` | _(generic option)_ | Target platform as os[/arch]; outranks the generic `--platform` |
| `PythonVersion` | `string` | newest fork | Target interpreter version |
| `Concurrency` | `int` | `10` | Parallel PyPI API requests |

## Dependency types

| Common flag | Python equivalent | What it includes |
|-------------|------------------|------------------|
| `--include-dev` | dependency groups | The project's dependency groups (uv and poetry, in any of their spellings): groups do not land in built distributions, so they are development-time by construction. Edge type: `devDependency`. A requirements file has no dev concept: no-op there. |
| `--include-build` | _(no-op)_ | Build backend requirements are not locked and are not included. |
| `--include-optional` | extras | The project's own extras. Edge type: `optionalDependency`. An extra named on a dependency edge (`requests[socks]`) is always followed: the parent asked for it. No-op for requirements files. |

## Strengths

- **Fully offline graph.** Everything but licenses comes from the lock:
  no network, no Python interpreter, no external binaries.
- **Verifiable hashes.** Each node is hashed with the exact file its
  environment installs, which is what PyPI attestations and
  `pip --require-hashes` bind to.
- **Environment-aware.** Marker evaluation (PEP 508) and version
  ordering (PEP 440) are held to Python's own `packaging` library by a
  checked-in oracle corpus, and the whole extraction is held to
  `uv export` by a conformance suite.
- **Workspaces.** Every workspace member roots the graph, and member
  edges resolve to the member's node.
- **Git dependencies.** Recorded with their resolved commit, from the
  URL fragment uv locks.

## Weaknesses

- **Not every tool yet.** Pipenv (`Pipfile.lock`), pdm and the
  standardized `pylock.toml` (PEP 751) are not read, and a
  `pyproject.toml` with no lockfile and no requirements file next to it
  is not a codebase this decomposer finds.
- **One environment per extraction.** The SBOM describes one platform
  and Python version. Covering several means several extractions; the
  edges cannot yet carry the markers themselves.
- **Linux assumes glibc.** Wheel selection matches `manylinux` tags;
  `musllinux` (Alpine-style) wheels are never chosen.
- **Lockfile licenses need the network.** With networking disabled, a
  lockfile extraction is license-empty, honestly. Installed
  environments do not have this problem.
- **A compiled requirements file's hashes are not attributable.** The
  format lists every artifact's hash without naming the artifacts, so
  those nodes carry no hash rather than a guessed one.
- **Path and directory dependencies carry no metadata.** They point at
  local content the locks say little about.

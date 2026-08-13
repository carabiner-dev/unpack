# Python Decomposer

**Location:** `source/python/`

Reads Python codebases managed by [uv](https://docs.astral.sh/uv/). The
whole dependency graph comes from `uv.lock`: versions, edges, environment
markers and artifact hashes are all resolved in the lock, so extraction
needs no network access and no Python interpreter.

## How it works

1. Parses `uv.lock` (schema version 1). The manifest is not read: the
   lock is self-contained.
2. Builds the target environment: an operating system, an architecture
   and a Python version. A lock resolves every environment the project
   supports at once; an extraction reads it for one, so one package
   appears at one version.
3. Walks the graph from the project's own packages. Edges keep or lose
   their place by their environment markers (PEP 508), evaluated against
   the target; a package whose resolution forked over the environment
   space contributes the entry the edges select.
4. Hashes every node with the SHA-256 of the distribution artifact the
   target environment would install: the most specific compatible wheel
   by its filename tags, installer-style, with the sdist as fallback.
5. With networking enabled, enriches registry packages from the PyPI
   JSON API: licenses, descriptions, homepages and repositories, none of
   which the lock carries.

All package names are normalized (PEP 503) everywhere: `Flask`,
`flask` and `FLASK` are one project.

## Targeting an environment

The graph is platform-conditional in Python, so the extraction resolves
for one concrete environment:

| Setting | CLI | Default |
|---------|-----|---------|
| Platform | `--platform os[/arch]` | the platform unpack runs on |
| Python version | `--python-version` | the newest version the lock's own resolution forks mention, falling back to the floor of `requires-python` |

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
| Name | `uv.lock` | PEP 503 normalized |
| Version | `uv.lock` | The version the target environment resolves to |
| PURL | computed | `pkg:pypi/{name}@{version}` |
| Download URL | `uv.lock` | The selected artifact's URL; a git source's URL for git dependencies |
| Hash (SHA-256) | `uv.lock` | The selected artifact's hash — the file PyPI attestations (PEP 740) bind to |
| Repository | `uv.lock` / PyPI API | `ExternalReference_VCS`; for git dependencies includes the resolved commit |
| License | PyPI API | See below |
| Description | PyPI API | The package summary |
| Homepage | PyPI API | Set as `UrlHome` |
| Documentation | PyPI API | `ExternalReference_DOCUMENTATION` |

### Licenses

`uv.lock` carries no license data at all, so licenses only appear with
networking enabled. PyPI states them in three places, tried best first:

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
| `--include-dev` | dependency groups | The project's dependency groups (PEP 735), `dev` and any other: groups do not land in built distributions, so they are development-time by construction. Edge type: `devDependency`. |
| `--include-build` | _(no-op)_ | Build backend requirements are not locked by uv and are not included. |
| `--include-optional` | extras | The project's own extras (`optional-dependencies`). Edge type: `optionalDependency`. An extra named on a dependency edge (`requests[socks]`) is always followed: the parent asked for it. |

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

- **uv only.** Projects managed by Poetry, Pipenv, pdm or plain
  `requirements.txt` are not read yet, and a `pyproject.toml` with no
  `uv.lock` next to it is not a codebase this decomposer finds.
- **One environment per extraction.** The SBOM describes one platform
  and Python version. Covering several means several extractions; the
  edges cannot yet carry the markers themselves.
- **Linux assumes glibc.** Wheel selection matches `manylinux` tags;
  `musllinux` (Alpine-style) wheels are never chosen.
- **Licenses need the network.** With networking disabled, every node
  is license-empty, honestly.
- **Path and directory dependencies carry no metadata.** They point at
  local content the lock says little about.

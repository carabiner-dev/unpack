# .NET (NuGet) Decomposer

**Location:** `source/nuget/`

Reads .NET projects (C#, F#, Visual Basic) from the lockfile NuGet
writes, `packages.lock.json`. The .NET SDK is not run and extraction is
offline.

A project has a lockfile when it is restored with
`RestorePackagesWithLockFile` set. One restored without is not found:
its package references are in the project file, with version ranges and
none of what they bring in.

## How it works

1. `FindCodeBases` finds the directories holding a `packages.lock.json`,
   which is beside the project file.
2. The lockfile is read in any of its three schemas. The first two hold
   their targets under `dependencies`; the third holds them at the root
   of the document, keyed by alias.
3. A lockfile resolves the project once for each **target**: a framework
   (`net8.0`, `.NETFramework,Version=v4.8`), or a framework and a
   runtime (`net8.0/win-x64`). Each resolution is a graph, and the
   lockfile holds it whole: every entry lists what it depends on.
4. The graph produced is the **union** of the targets' graphs:
   - The project depends on what it references itself: the `Direct`
     packages and the `Project` entries.
   - Each entry depends on what its `dependencies` name, looked up in
     the same target whatever the case of the id.
   - A package at a version is one node however many targets resolve it,
     and each target is named on it. A package two targets resolve to
     two versions is two nodes.
   - A package resolved for a target that nothing there requires hangs
     from the project, so that nothing resolved is lost.

The resolution for a runtime only lists what differs from the
framework's own, so an id it does not have is looked up in the
framework's.

A dependency no entry of the target answers to is left out: it is a
reference assembly of the framework (`System.Core`), which no package
provides.

### Entry types

| `type` | What it is |
|--------|------------|
| `Direct` | A package the project references |
| `Transitive` | A package another package brings in |
| `CentralTransitive` | A transitive package whose version the repository pins centrally (`Directory.Packages.props`) |
| `Project` | Another project of the solution the project references. It is no package: it has no version, and its node is `pkg:generic` |

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | entry key | The package's id as the lockfile writes it |
| Version | `resolved` | |
| PURL | computed | `pkg:nuget/{id}@{version}`; `pkg:generic/{name}` for a project |
| `nuget:type` | `type` | Once for each type it has among the targets |
| `nuget:target` | target key | Once for each target that resolves it |
| `nuget:requested` | `requested` | The range asked for, as `[13.0.3, )` |
| `nuget:content-hash` | `contentHash` | See below |

There is no license, no supplier and no download location: the lockfile
states none, and does not say which feed a package came from.

### The content hash is not a file hash

`contentHash` is a SHA-512, in base64, that NuGet computes over a
package's content **without its signature**, so that the hash stays what
it was when a signature is added. Packages on nuget.org are signed, so
hashing the `.nupkg` one downloads gives another value. For
`Newtonsoft.Json` 13.0.3:

```
contentHash in a lockfile:  HrC5BXdl00IP9zeV…
SHA-512 of the .nupkg:      mbJSvHfRxfX3tR/U…
```

A reader given that value as the package's SHA-512 would find it does
not match the file, so it is a property and not one of the node's
hashes. It can be checked by NuGet, or against another lockfile.

## The root

| Field | Source |
|-------|--------|
| Name | The project file beside the lockfile (`App.csproj` is `App`) when there is one and only one; the directory name otherwise |
| Version | The version unpack reads from git |
| PURL | `pkg:nuget/{name}@{version}` |
| License | The project's license file; see [The codebase's own license](README.md#the-codebases-own-license) |

## Dependency types

The inclusion flags are no-ops. A lockfile does not tell a development
dependency (an analyzer, a source generator, a package with
`PrivateAssets="all"`) from the rest: that is in the project file.

## Generation context

`source`. The lockfile is read as it stands in the source tree, so a
document made from this data is a source SBOM: CycloneDX lifecycle
`pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Networking

None.

## Strengths

- **The whole graph, offline.** Direct and transitive are told apart and
  every edge is the lockfile's.
- **Every target.** What differs between frameworks and runtimes is in
  the graph, and each package says which targets have it.
- **Project references** are in the graph, with what they bring.
- **Central package management** needs nothing special: the lockfile
  holds the versions it resolved to.

## Weaknesses

- **Only projects with a lockfile.** Lockfiles are opt-in in .NET, and
  many projects have none. `PackageReference` items in project files,
  `Directory.Packages.props` and the older `packages.config` are not
  read.
- **No verifiable hash.** See above.
- **No licenses or suppliers**, and the feed a package came from is not
  known, so nothing is looked up.
- **Development dependencies are not told apart.**
- **One lockfile a directory.** A lockfile under another name
  (`packages.<project>.lock.json`, `NuGetLockFilePath`) is not found.
- **A solution is not one codebase.** Each project with a lockfile is
  its own, and a project referenced by several is a node in each of
  theirs.

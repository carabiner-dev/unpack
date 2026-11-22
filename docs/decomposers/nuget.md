# .NET (NuGet) Decomposer

**Location:** `source/nuget/`

Reads .NET projects (C#, F#, Visual Basic). The .NET SDK is not run and
extraction is offline.

A project is read from the best record it has:

| The project has | What is read | What it gives |
|-----------------|--------------|---------------|
| `packages.lock.json` | The lockfile NuGet writes when a project is restored with `RestorePackagesWithLockFile` | The whole graph, resolved, for every target |
| no lockfile | Its project file and the repository's props files; see [Without a lockfile](#without-a-lockfile) | The packages it asks for, at the versions asked for |
| `packages.config` | The older list of installed packages | Every package installed, at its exact version, with no edges |

Lockfiles are opt-in in .NET and most projects have none, so the second
row is the common case. What it gives is less, and each node says so.

## How it works

1. `FindCodeBases` finds the directories holding a `packages.lock.json`,
   a project file (`.csproj`, `.fsproj`, `.vbproj`) or a
   `packages.config`. With a lockfile, the rest of this section
   applies.
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

## Without a lockfile

A project with no lockfile is read from what it asks for. The graph is
flat and holds **direct references only**: what those packages bring in
is decided by a restore and written nowhere in the source. Every such
node has a `nuget:read-from` property.

### Project files

`PackageReference` items are read from the project file, wherever they
are in it: in an item group, or in the branches of a `Choose`. So are
the ones the repository gives every project, which MSBuild imports from
the nearest of each of these above the project, up to the root of the
git repository:

| File | What it gives the projects below it |
|------|-------------------------------------|
| `Directory.Packages.props` | The versions managed centrally (`PackageVersion`), and `GlobalPackageReference` items |
| `Directory.Build.props`, `Directory.Build.targets` | `PackageReference` items of their own, and properties |

The version of a reference is, in this order: its `VersionOverride`,
its `Version` (attribute or child element), the central file's
`PackageVersion` for its id. A property in it (`$(SerilogVersion)`) is
filled in from the project file and then from those files. An `Update`
or `Remove` item changes an item declared elsewhere and names no
package.

What is asked for is not always one version:

| Asked for | Node version | |
|-----------|--------------|--|
| `13.0.3` | `13.0.3` | The lowest NuGet may pick, and the one it picks unless something else in the graph asks for a higher one |
| `[4.2.0]` | `4.2.0` | Exactly that |
| `[8.0.0, 9.0.0)`, `8.*` | none | A range or a floating version resolves to what only a restore knows |
| `$(SetElsewhere)`, nothing | none | A property the source does not define, or no version anywhere |

The text asked for is always on the node, in `nuget:requested`.

A reference with `PrivateAssets="all"` does not flow to what uses the
project: analyzers, source generators and build tooling are referenced
that way, and a `GlobalPackageReference` always is. Those are
`devDependency` edges, included with `--include-dev`.

A condition on a reference or its item group, most often a target
framework, is on the node as `nuget:condition`. It is not evaluated:
the reference is listed whatever it says.

`ProjectReference` items are the other projects of the solution, as
`pkg:generic` nodes named after their project file.

### packages.config

The older kind of project lists every package installed for it, the
ones its references brought in included, each at its exact version.
They are all dependencies of the project: the file does not say which
brought which. One marked `developmentDependency="true"` is a
`devDependency`. The repository's props files are not applied to such a
project.

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
| `nuget:read-from` | | `project` or `packages.config`, on a node read without a lockfile |
| `nuget:condition` | `Condition` | On a node read from a project file |

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

With a lockfile the inclusion flags are no-ops: a lockfile does not
tell a development dependency (an analyzer, a source generator, a
package with `PrivateAssets="all"`) from the rest.

Without one, `--include-dev` includes the references that do not flow
to the project's users, and the development dependencies of a
`packages.config`.

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

- **Without a lockfile, direct references only.** Nothing transitive,
  and a version is the one asked for, which a restore may raise.
- **MSBuild is not evaluated.** Conditions are recorded and not
  applied; only the nearest props file of each kind is read, not what
  it imports; a property set on the command line, or computed, is not
  known; and references a custom SDK or target adds are not seen.
- **No verifiable hash.** See above.
- **No licenses or suppliers**, and the feed a package came from is not
  known, so nothing is looked up.
- **Development dependencies are not told apart.**
- **One lockfile a directory.** A lockfile under another name
  (`packages.<project>.lock.json`, `NuGetLockFilePath`) is not found.
- **A solution is not one codebase.** Each project with a lockfile is
  its own, and a project referenced by several is a node in each of
  theirs.

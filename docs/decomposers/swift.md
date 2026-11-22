# Swift Decomposer

**Location:** `source/swift/`

Reads projects whose dependencies are managed with the
[Swift Package Manager](https://www.swift.org/documentation/package-manager/),
from its lockfile, `Package.resolved`. Swift is not run and extraction is
offline.

SwiftPM generates SBOMs itself since Swift 6.4
([SE-0509](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0509-swift-sboms-via-swiftpm.md)):
`swift package generate-sbom`. This decomposer names, versions and
identifies packages by the same rules, taken from SwiftPM's source, so
that a package read here and the same package in SwiftPM's SBOM agree.
It cannot give all SwiftPM gives; see
[Compared with SwiftPM's SBOMs](#compared-with-swiftpms-sboms).

## How it works

1. `FindCodeBases` finds the directories holding a `Package.resolved`:
   beside the `Package.swift` of a package, and for an Xcode project or
   workspace inside its bundle
   (`App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/`,
   `App.xcworkspace/xcshareddata/swiftpm/`).
2. The lockfile is read in any of its three schemas. The first nests its
   pins and names them by repository URL; the second and third name them
   by identity and kind. A schema newer than those is read as the third,
   with a warning.
3. Each pin is a package, and a `dependsOn` of the project.

The manifest, `Package.swift`, is a Swift program and is not read: a
package with no lockfile is not found.

## Data produced per dependency

| Field | Source | Notes |
|-------|--------|-------|
| Name | `identity` | As SwiftPM knows the package: the last element of its repository's URL in lower case, or `scope.name` for a registry package |
| Version | `state` | The version it is pinned to. For a package following a branch or pinned to a bare commit, the commit, as in SwiftPM's SBOMs |
| PURL | computed | See below |
| Repository | `location` | `ExternalReference_VCS`, with the commit as its SHA-1 |
| `swift:kind` | `kind` | `remoteSourceControl`, `localSourceControl` or `registry` |
| `swift:revision` | `state.revision` | The commit |
| `swift:branch` | `state.branch` | The branch followed, when there is one |

There is no license and no supplier: the lockfile states neither, and
nor do SwiftPM's SBOMs yet.

### PURLs

Built as SwiftPM builds them (`PURL.swift`):

| Package | PURL |
|---------|------|
| A repository | `pkg:swift/{host}/{first path element}/{identity}@{version}`: `pkg:swift/github.com/apple/swift-asn1@1.5.0` |
| A registry package | `pkg:swift/{scope}/{name}@{version}` |
| A local repository | `pkg:swift/{identity}@{version}?path={path}` |

Two things to know. The namespace is the host and the **first** element
of the path only, so a repository in a nested group
(`gitlab.example.com/platform/ios/kit`) is
`pkg:swift/gitlab.example.com/platform/kit`. And the path of a local
repository is percent-encoded here, as a purl has it, where SwiftPM
writes it bare; the two read as the same purl.

### No hashes

The commit a package is pinned at identifies its sources exactly, and is
on the repository reference. It is no hash of an artifact, so it is not
among the node's hashes. The lockfile holds no checksum, of a registry
package's archive either.

## The root

| Field | Source |
|-------|--------|
| Name | The directory name; for a lockfile inside an Xcode bundle, the project or workspace the bundle is of |
| Version | The version unpack reads from git |
| PURL | `pkg:swift/{name in lower case}@{version}` |
| License | The project's license file; see [The codebase's own license](README.md#the-codebases-own-license) |

## Compared with SwiftPM's SBOMs

| In SwiftPM's SBOM | Here |
|-------------------|------|
| A component for each package: identity, version, purl | The same |
| The repository and commit of each package | The same |
| A component for each product of a package (`swift-asn1:SwiftASN1`) | Not known: products are declared in `Package.swift` |
| Edges between packages and between products | Not known: the lockfile is a flat list |
| Whether a package is only for the tests | Not known |
| Whether a package builds an application or a library | Not known; every dependency is a library here |
| Licenses, hashes | In neither |

SwiftPM has the rest because it evaluates the manifest of every package.
Where the Swift toolchain is at hand, its SBOM is the fuller record, and
`unpack sbom` reads it.

## Dependency types

The inclusion flags are no-ops: the lockfile does not tell test or
plugin dependencies from the rest.

## Generation context

`source`. The lockfile is read as it stands in the source tree, so a
document made from this data is a source SBOM: CycloneDX lifecycle
`pre-build`, SPDX 3 type `source`. See
[Generation context](README.md#generation-context).

## Networking

None.

## Strengths

- **Exact versions and commits**, from SwiftPM's own record.
- **The same names as SwiftPM's SBOMs**, purls included.
- **Xcode projects are found**, which have no `Package.swift`.
- **Offline, with no toolchain.**

## Weaknesses

- **The graph is flat.** Every package hangs from the root; which of
  them the project asks for itself is not known.
- **No products.** SwiftPM's SBOMs list them; they are in the manifest.
- **No licenses, suppliers or hashes.**
- **Libraries commit no lockfile.** By convention a Swift package that
  is a library leaves `Package.resolved` out of its repository, and is
  not found.
- **The path of a local repository is in the document**, as it is in the
  lockfile: an absolute path of the machine that resolved it.
- **Only SwiftPM.** CocoaPods (`Podfile.lock`) and Carthage
  (`Cartfile.resolved`) are not read.

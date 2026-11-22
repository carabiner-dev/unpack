# Java Archive Decomposer

**Location:** `artifact/jar/`
**Name:** `jar`

Reads the packages bundled in Java archives: jars, and the WARs, EARs
and executable jars that carry their dependencies inside them. Nothing
but the file is needed. It is a decomposer of the **artifact** unpacker
and runs wherever that unpacker runs: on a file or directory handed to
`unpack artifact`, and inside every container image `unpack image`
scans. A Java service in an image is reported with its libraries next
to the OS inventory.

## How it works

1. **Filter.** Files named as Java archives are read: `.jar`, `.war`,
   `.ear`, `.rar`, `.sar`, `.par`, and Jenkins plugins (`.hpi`, `.jpi`).
   The name is enough: an executable jar may open with a launch script
   and not with a zip's magic number. A file that turns out to be no zip
   is disowned without an error.
2. **Who the archive is.** See [Identity](#identity).
3. **What is bundled in it**, in the two ways archives bundle things:
   - **Nested:** whole archives inside the archive, as in
     `WEB-INF/lib/` of a WAR, `BOOT-INF/lib/` of a Spring Boot jar, or
     the WARs and jars of an EAR. Each is opened and read the same way,
     up to four deep.
   - **Shaded:** packages unpacked into the archive, as the Maven Shade
     plugin does. The classes are merged and only the `pom.properties`
     of each package remains to say it is there.
4. **Graph.** The archive is the root, and each package bundled in it is
   a `dependsOn` of it; a nested archive has what is bundled in it in
   turn. The same file bundled twice, a library in two WARs of an EAR,
   is one node.
5. **Root.** The artifact unpacker wraps the result under a file node
   carrying the path and SHA-256 of the archive.

```
app/shop.jar                                   (file, sha256)
  └ generatedFrom ─▶ pkg:maven/org.example/shop@1.4.0
                        ├ dependsOn ─▶ pkg:maven/com.google.guava/guava@33.2.0-jre
                        └ dependsOn ─▶ pkg:maven/org.slf4j/slf4j-api@2.0.13
```

The edges say what is bundled in what, which is what an archive
records. Which of the bundled packages requires which is not in it: a
WAR's libraries all hang from the WAR.

## Identity

An archive, or a package unpacked into one, is named from the surest
source it has. The `java:identified-by` property says which.

| Source | What is read | PURL |
|--------|--------------|------|
| `pom.properties` | `META-INF/maven/{group}/{artifact}/pom.properties`, which Maven writes into every artifact it builds: group, artifact and version | `pkg:maven/{group}/{artifact}@{version}` |
| `manifest` | `META-INF/MANIFEST.MF`. The name is the first of `Bundle-SymbolicName`, `Automatic-Module-Name` and `Implementation-Title`; the version the first of `Bundle-Version` and `Implementation-Version` | `pkg:generic/{name}@{version}` |
| `filename` | The file's name without its extension, with no version | `pkg:generic/{name}` |

A file name is not taken apart for a version: `mystery-lib-2.0.jar` is
named `mystery-lib-2.0`. Where the version ends and the name begins is a
guess, and a wrong version is worse than none.

An archive holding the `pom.properties` of several packages is the one
its file is named after, the longest such when more than one fits, and
the rest were unpacked into it. When the file is named after none of
them, none is its own, and the manifest or the file name says who it
is: a shaded jar is often named for what it is and not for the artifact
that built it.

The manifest's `Implementation-Vendor`, or `Bundle-Vendor`, is the
supplier, and failing those the organization the archive's own POM
names.

## Licenses

An archive may say how it is licensed in three places. They are tried
in this order, and the first that says anything settles it; the
`java:license-from` property says which did.

| Source | What is read |
|--------|--------------|
| `pom.xml` | The POM Maven puts beside `pom.properties`, when it declares `<licenses>` itself |
| `manifest` | The `Bundle-License` header: identifiers or URLs, which OSGi bundles carry and many plain jars too |
| `license-file` | A `LICENSE`, `LICENCE` or `COPYING` file at the root of the archive or in its `META-INF`, whose text is recognized |

Names and URLs are normalized through the shared license catalog. A
name it does not recognize is passed on as written; a URL it does not
recognize is no license to pass on, and is left out.

The order matters less than it looks, because the first source is
often silent: most projects inherit their license from a parent POM,
and the parent is not in the archive. `commons-lang3` is such a jar,
and its license is read from its manifest.

A package **shaded** into an archive takes the license its own POM
declares, and no other: the manifest is the outer archive's, and a
license file in an archive several packages were unpacked into may be
any of theirs. For the same reason the license file is not read for an
archive that has shaded packages.

## Data produced

| Field | Source | Notes |
|-------|--------|-------|
| Name, Version, PURL | see [Identity](#identity) | |
| Supplier | manifest, `pom.xml` | The vendor, or the POM's organization, as an organization |
| License | `pom.xml`, manifest, license file | See [Licenses](#licenses) |
| Hashes | computed | SHA-256 and SHA-1 of a nested archive's file. A shaded package has no file of its own and none; the outermost archive's is on the file node |
| Primary purpose | manifest | `APPLICATION` for an archive with a `Main-Class`, `LIBRARY` otherwise |
| `java:identified-by` | | `pom.properties`, `manifest` or `filename` |
| `java:embedding` | | `nested` or `shaded` |
| `java:path` | | Where a nested archive is inside the one that holds it |
| `java:main-class` | manifest | |
| `java:license-from` | | `pom.xml`, `manifest` or `license-file` |

The SHA-1 is there because Maven repositories publish and index jars by
it: it is the hash to look a jar up with.

## Where it runs

Like the [Go binary decomposer](gobinary.md), this one answers **images
and system roots** to the `api.SubjectDefaults` trait and not
**codebases**: the jars lying in a source tree are build outputs and
test fixtures. The same switches apply: `--skip-artifact jar`
on either command, `--no-artifacts` on `unpack image`, and the
`ArtifactDecomposers` map on the image unpacker. The default skip list
for system directories applies too, so the jars of a distribution's own
packages under `/usr/share/java` are left to the system decomposers.

## Limits

To keep a broken or hostile archive from exhausting memory: archives are
read four deep; a nested archive larger than 256 MB is not read, as it
has to be held in memory to be opened; a manifest or `pom.properties`
larger than 1 MB is passed over. What is skipped is logged at the
`debug` level.

## Generation context

`analyzed`. The decomposer reads an archive that is already built, so a
document made from its data is an analyzed SBOM: CycloneDX lifecycle
`post-build`, SPDX 3 type `analyzed`. See
[Generation context](README.md#generation-context).

## Strengths

- **Works on the deployed thing.** No source, no build, no repository.
- **Exact for Maven-built archives.** Coordinates and versions are the
  ones Maven wrote.
- **Sees through bundling**: nested archives to any depth that occurs,
  and shaded packages.
- **Hashes of the files bundled**, which a lookup on a repository can
  use.

## Weaknesses

- **Not every build writes `pom.properties`.** Gradle, Ant and Bazel do
  not unless told to. Their archives are known by a manifest, when it
  says anything, or by a file name with no version, and a shaded jar of
  theirs shows nothing of what was unpacked into it.
- **No dependency structure.** Bundled is all that is known.
- **Not every archive says its license.** One whose POM inherits it,
  with no `Bundle-License` and no license file, has none here: the
  parent POM is on a repository, and no repository is asked.
- **A shaded package has no hash**, and a relocated one keeps its
  `pom.properties` under the package's original name.
- **Class files are not read.** A jar with no metadata is not
  identified by its contents.

# Writing an Unpacker or a Decomposer

This guide is for contributors who want to teach unpack to read dependency
data from something new: a package ecosystem, an installed-package database,
or an entirely new kind of subject such as a binary or a VM image.

It explains the three roles the extraction pipeline is built from, how they
assemble, and how to implement each one. The per-ecosystem pages in this
directory (see the [README](README.md)) describe what the existing
decomposers do; this page is about how they are put together.

## The three roles

Every extraction involves a **subject**, an **unpacker** and, usually, one or
more **decomposers**. The interfaces live in `api/v1`.

| Role | Interface | Knows about | Examples |
| --- | --- | --- | --- |
| Subject | `api.DecomposableSubject` | Where the data is | `dependencies.Codebase` (a path), `system.Filesystem` (an `fs.FS`), `artifact.File` (one built artifact), `image.Reference` (an OCI ref), `release.Reference` (a forge release), `sbom.Subject` (a file) |
| Unpacker | `api.Unpacker` | One *kind* of subject | `dependencies.Unpacker` (codebases), `system.Unpacker` (systems), `artifact.Unpacker` (built artifacts), `image.Unpacker`, `release.Unpacker`, `sbom.Unpacker` |
| Decomposer | `api.Decomposer` | One *flavor* of that kind | `source/golang` (go.mod), `source/npm`, `system/apk`, `system/deb`, `artifact/gobinary` (Go executables), `release.Decomposer` |

### Subjects

A subject is the thing being unpacked. The interface is deliberately tiny:

```go
type DecomposableSubject interface {
    DecomposableType() string
}
```

`DecomposableType` returns a stable identifier (`"codebase"`, `"system"`,
`"image"`, ...). Everything else a subject carries (a path, a filesystem, a
reference) is a plain field on the concrete type. The unpacker that handles a
subject type-asserts to the concrete type to get at it.

### Unpackers

An unpacker is the entry point. It owns the decomposers for its kind of
subject and orchestrates them:

```go
type Unpacker interface {
    Extract(context.Context, DecomposableSubject) ([]*sbom.NodeList, error)
    RegisterDecomposer(Decomposer)
    UnregisterDecomposer(Decomposer)
}
```

`Extract` returns a slice of [protobom](https://github.com/protobom/protobom)
NodeLists, one per thing found. A codebase path holding a Go module and an
npm project yields two; a container image yields one, rooted at a node
describing the image.

### Decomposers

A decomposer cracks one flavor of a subject and renders it as a NodeList:

```go
type Decomposer interface {
    Extract(*DecomposerOptions) (*sbom.NodeList, error)
    Requirements(*DecomposerOptions) []Requirement
    DefaultOptions() any
}
```

- `Extract` does the work. `DecomposerOptions` is an ephemeral, per-call
  bag the unpacker fills from its own configuration: the working directory,
  the version and commit to stamp on the root node, the networking level,
  the platform and the dependency-inclusion flags.
- `DefaultOptions` returns the decomposer's own options struct with its
  defaults. Callers use it to discover what can be tuned.
- `Requirements` declares what the decomposer needs at runtime (network
  access to a host, an executable). Implementations live in the
  `requirements` package. Nothing in the pipeline enforces them today; they
  exist so hosts and CLIs can check and report before running. Pure-Go
  decomposers return nil.

Unpackers extend the base interface when their subject needs a different
entry point. The three that matter:

- `api.SourceDecomposer` adds `FindCodeBases(*code.PathIndex) ([]string, error)`.
  The codebase unpacker only runs decomposers that implement it.
- `system.SystemDecomposer` adds `ExtractFromFS(fs.FS, *DecomposerOptions)`.
  The system unpacker calls this instead of `Extract` so it can hand in
  filesystems that are not on disk (a squashed image, a tarball).
- `artifact.Decomposer` adds a stable `Name()`, a cheap
  `Matches(fs.FileInfo, header []byte)` filter and
  `ExtractArtifact(io.ReaderAt, path, *DecomposerOptions)`. The artifact
  unpacker probes every file of its subject through the filter and reads
  only the ones that pass.

One more interface is optional and read by *parents*, not by the
decomposer's own unpacker:

- `api.SubjectDefaults` adds `DefaultSubjects() []string`: the parent
  subject types (`"image"`, `"system"`, ...) under which the decomposer
  runs by default. A parent routing a child subject asks the child
  unpacker for its defaults (`artifact.Unpacker.DefaultsFor("image")`),
  adjusts them to what its caller asked for, and sets them as the child's
  options. The trait informs the defaults; the options decide what runs.
  `artifact/gobinary` uses it to run inside images but not on codebases.

## How they assemble

```
   CLI / library caller
         │  builds a subject, picks the unpacker, calls Extract
         ▼
   ┌──────────────┐        ┌───────────────────────────────────┐
   │   Unpacker   │──────▶ │ Decomposer  Decomposer  Decomposer│
   └──────────────┘        └───────────────────────────────────┘
         │                              │
         │ discovers a child subject    │ returns *sbom.NodeList
         ▼                              ▼
   api.UnpackerFor(child) ──▶ another Unpacker ──▶ its decomposers
```

**Callers only pick the initial subject and unpacker.** `unpack extract`
builds a `dependencies.Codebase` and a `dependencies.Unpacker`;
`unpack image` builds an `image.Reference` and an `image.Unpacker`. From
there the pipeline is the same `Extract` call for everything.

**Unpackers fan out to decomposers.** How depends on the kind of subject:

- The codebase unpacker indexes the directory tree once (respecting
  `.gitignore` and ignore patterns), asks every `SourceDecomposer` where
  its codebases are via `FindCodeBases`, then calls `Extract` once per
  location with `WorkDir` set to that directory. Each call yields one
  NodeList.
- The system unpacker opens the subject's filesystem and calls
  `ExtractFromFS` on every decomposer. A decomposer whose database is not
  present returns `(nil, nil)` and is skipped. Errors from one decomposer do
  not stop the others; they are joined and returned alongside the lists
  that did succeed.
- The artifact unpacker lists the regular files of its subject (one file,
  a directory, an image filesystem), reads the first 64 bytes of each and
  offers them to every enabled decomposer's `Matches`. The first
  decomposer to claim a file in `ExtractArtifact` wins; `(nil, nil)`
  disowns it. Each artifact found becomes a list rooted at a file node
  with the path and SHA-256, related through `generatedFrom` to the graph
  the decomposer read out of it.
- The release unpacker hands each decomposer the reference through the
  driver options and collects what comes back.

**Unpackers compose through the registry.** `api/v1/registry.go` maps a
subject type to a builder. Unpacker packages self-register from `init()`:

```go
func init() {
    api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}
```

While working its own subject an unpacker may find a child subject of a
different kind. It does not need to know who handles it: it wraps it in the
right subject type and routes it with `api.UnpackerFor`. The image unpacker
is the reference example. It squashes the layers into an `fs.FS`, wraps that
in a `system.Filesystem` and lets the registry find the system unpacker:

```go
subject := &system.Filesystem{FS: fsys}
unpacker, err := api.UnpackerFor(subject)
if err != nil {
    return nil, fmt.Errorf("locating system unpacker: %w", err)
}
lists, err := unpacker.Extract(ctx, subject)
```

The image unpacker then relates every returned list to its own image node
with a `contains` edge. This is how the graph nests: image → packages, or,
in the future, filesystem → codebases → dependencies.

**One piece of data may be several subjects.** The registry maps a subject
type to one unpacker, so a parent that wants more than one kind of child
wraps the same data more than once. The image unpacker routes its squashed
filesystem twice: as a `system.Filesystem` for the installed packages and
as an `artifact.Filesystem` for the executables, and hangs both results
under the image node. Fan-out is the parent's explicit job.

**The parent picks the edge.** A child unpacker returns lists rooted at
the things it found and never emits the edge upward: the artifact
unpacker roots each list at the file, the system unpacker at each
package. What that root *is* to the parent (`contains` for an image,
something else for another parent) is the parent's call when it relates
the list.

**Options do not flow through the registry.** `api.UnpackerFor` returns a
plain `api.Unpacker`, so a parent that needs to configure the child
type-asserts to the concrete unpacker and sets its `Options` (the image
unpacker does this to forward `IncludeFiles` to the system unpacker and
the artifact switches and networking level to the artifact unpacker).
This works for one hop. Image → artifact → Go proxy networking already
shows the seams; a shared options carrier is a known follow-up.

Note that a blank import of the child's package is what triggers its
`init()`. An unpacker that routes to another must import it (the image
unpacker imports `system` and `artifact` for the subject types anyway).

## Which one should you write?

| You want to add... | Write | Register it in |
|--------------------|-------|----------------|
| A new language or package manager read from source (lock and manifest files) | A `SourceDecomposer` under `source/<eco>/` | `dependencies.NewUnpacker` |
| A new installed-package database or installed environment found on a filesystem | A `SystemDecomposer` under `system/<eco>/` | `system.NewUnpacker` |
| A new kind of built artifact that carries its own dependency data (an executable format, an archive with embedded metadata) | An `artifact.Decomposer` under `artifact/<kind>/` | `artifact.NewUnpacker` |
| A new kind of thing to unpack (a binary, a VM image, a registry, ...) | A subject type plus an unpacker in a new package, and the decomposers it needs | The registry, from `init()` |

Most contributions are the first row. The rest of this page walks through
each in turn.

## Writing a source decomposer

Create `source/<ecosystem>/` with a `decomposer.go` and put the parsing of
each file format in its own file (`gemlock.go`, `cargolock.go`, ...). Every
Go file starts with the SPDX header:

```go
// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0
```

### 1. The type, its options and the interface assertions

```go
package example

var (
    _ api.Decomposer       = (*Decomposer)(nil)
    _ api.SourceDecomposer = (*Decomposer)(nil)
)

func New() *Decomposer { return &Decomposer{} }

type Decomposer struct{}

// Options configures the example decomposer.
type Options struct {
    RegistryURL string
    HTTPClient  *http.Client // custom client, for tests
}

var defaultOptions = Options{
    RegistryURL: "https://registry.example.org",
}

func (d *Decomposer) DefaultOptions() any { return defaultOptions }

// getOptions reads the decomposer's own options out of the shared bag,
// falling back to the defaults.
func (d *Decomposer) getOptions(opts *api.DecomposerOptions) *Options {
    if opts != nil {
        if o, ok := opts.GetDriverOptions(d).(*Options); ok {
            return o
        }
    }
    return &defaultOptions
}
```

The compile-time assertions are the convention across the repo and catch a
missing method at build time rather than at registration time.

Decomposer-specific options travel inside `DecomposerOptions` in a bag keyed
by the decomposer's Go type. The unpacker fills the bag from
`dependencies.Options.Drivers`; the decomposer reads its own entry with
`GetDriverOptions`. Only add an option when the value cannot be derived from
the codebase. Anything that applies across ecosystems (networking, dev and
build inclusion, platform) already exists on `DecomposerOptions`. Use those
rather than duplicating them.

### 2. Requirements

```go
func (d *Decomposer) Requirements(_ *api.DecomposerOptions) []api.Requirement {
    return nil
}
```

All shipped decomposers are pure Go and return nil. Do not shell out to the
ecosystem's own tooling (`go`, `npm`, `cargo`): parse the files yourself.
That keeps unpack portable and lets it read codebases it cannot build. If
you genuinely need the network, return a `requirements.Network` so callers
can report it.

### 3. Finding codebases

```go
func (d *Decomposer) FindCodeBases(index *code.PathIndex) ([]string, error) {
    return index.FindFileLocations("example.lock")
}
```

The unpacker builds one `code.PathIndex` per input path: a map of
directories to the file names they contain, minus anything ignored. Return
the directories that hold a codebase you can extract. Pick the file that
marks a project root (`go.mod`, `Cargo.toml`, `Gemfile.lock`), not one that
appears in every subdirectory. Monorepos return several paths; each becomes
a separate NodeList with its own root node.

The language key under which the decomposer is registered (see step 6) is
also the prefix of the codebase IDs shown by `unpack ls`, as in
`golang:services/api`. Choose a short, lowercase name.

### 4. Extract

```go
func (d *Decomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
    dOpts := d.getOptions(opts)

    lock, err := parseLock(filepath.Join(opts.WorkDir, "example.lock"))
    if err != nil {
        return nil, fmt.Errorf("parsing example.lock: %w", err)
    }

    nl := sbom.NewNodeList()
    root := rootNode(lock, opts)
    nl.AddRootNode(root)

    // ... add dependency nodes and edges ...

    if opts.Networking >= api.NetworkEssential {
        d.enrich(nl, dOpts, opts.Networking)
    }
    return nl, nil
}
```

Read local files first and produce a complete graph from them. Treat the
network as enrichment layered on top, gated by the networking level:

| Level | Allowed |
|-------|---------|
| `NetworkDisabled` | Nothing. The result may be incomplete; say so in the docs. |
| `NetworkEssential` (default) | Calls needed to build the graph plus small metadata requests: registry JSON APIs, checksum files, a dependency's own manifest. |
| `NetworkFull` | Anything, including downloading whole artifacts to hash them or to classify a license file. |

Do enrichment concurrently with a bounded worker count and respect
`HTTPClient` from the options so tests can point you at an
`httptest.Server`.

### 5. NodeList conventions

These are what make the output of different decomposers look alike, and what
the SBOM serializers rely on.

**Exactly one root node per codebase.** It is a `Node_PACKAGE` named after
the project. The codebase unpacker errors on a NodeList without a root
element. Stamp the unpacker-supplied metadata on it:

- `opts.Version` becomes the root's `Version` and goes into its purl. The
  unpacker reads it from git tags when `ReadGitVersion` is on.
- `opts.CommitHash`, when set, becomes an `ExternalReference_VCS` on the
  root carrying the SHA-1.

**Every package node gets a purl.** Set it under
`SoftwareIdentifierType_PURL`. Follow the purl spec for the ecosystem's type
and percent-encode reserved characters; `packageurl-go` does this for you
(see `system/apk` and `release` for examples), while the source decomposers
build simple purls by hand. Look nodes up by purl with
`nl.GetNodesByIdentifier("purl", ...)` to avoid emitting the same
dependency twice. Node IDs are UUIDs (`uuid.NewString()`).

**Fill what the ecosystem gives you.** `Version`, `Licenses`, `Hashes`
(from the lock file, with the algorithm the ecosystem actually uses),
`UrlDownload`, `UrlHome`, `Suppliers`, `PrimaryPurpose` (usually
`Purpose_LIBRARY`). Leave a field empty rather than guess: a download URL
you cannot derive is better omitted than invented.

**Normalize licenses** with `license.Normalize(name, url)` from the shared
`license` package so output carries SPDX identifiers.

**Use typed edges.** Relate nodes with `nl.RelateNodeAtID(node, parentID, edge)`:

| Edge | Meaning |
|------|---------|
| `Edge_dependsOn` | Runtime dependency (the default) |
| `Edge_devDependency` | Development or test dependency; only emit when `opts.IncludeDev` |
| `Edge_buildDependency` | Build tooling; only emit when `opts.IncludeBuild` |
| `Edge_optionalDependency` | Optional dependency; only emit when `opts.IncludeOptional` |
| `Edge_contains` | Structural containment (a package's files, an image's packages) |

When the ecosystem has no notion of one of these categories, ignore the flag
and say so in the decomposer's documentation page. Keep transitive semantics
faithful: a dev dependency of a dependency is not a dev dependency of the
root.

**Resolve for one platform.** If the graph is conditional on the target
(Python markers, Go build constraints), read `opts.Platform` and resolve for
that; empty means the platform unpack runs on. Ecosystems with
platform-independent graphs ignore the field.

### 6. Register it

Built-in decomposers are constructed in `dependencies.NewUnpacker`, keyed by
language name:

```go
decomposers: map[string]api.Decomposer{
    "rust":    rust.New(),
    "golang":  golang.New(),
    // ...
    "example": example.New(),
},
```

Library users can add third-party decomposers at runtime with
`RegisterDecomposer`, which keys by Go type. The map above is for the
decomposers unpack ships with.

If your decomposer takes options that deserve a CLI flag, wire it in
`internal/cmd/extract.go` by appending a `dependencies.DriverConfig` to
`unpacker.Options.Drivers`, the way `--python-version` is handled.

### 7. Tests

- Put fixtures under `source/<ecosystem>/testdata/`, one directory per
  scenario (`simple`, `with-replace`, ...). Keep them tiny and hand-written.
  If a fixture must contain file names that are illegal on NTFS, pack it as
  a `tar.gz` and unpack it into an in-memory filesystem in the test rather
  than checking the tree out; CI runs on Windows.
- Test the parsers directly on the fixture files, then test `Extract`
  end to end with `WorkDir` pointing at a fixture and the network either
  disabled or pointed at an `httptest.Server` through the options.
- Assert on the shape of the graph: root purl, the set of dependency purls,
  the edge types under each inclusion flag. Use `testify/require`.
- Mark tests `t.Parallel()`. Table-driven tests may repeat literals freely;
  `goconst` is disabled for `_test.go` files.
- Where a reference implementation exists (a package manager that can list
  what it installed), consider a conformance test that compares your output
  with it, skipping when the tool is not available. `system/apk/conformance_test.go`
  shows the pattern.

### 8. Documentation

Add `docs/decomposers/<ecosystem>.md` following the layout of the existing
pages: location, how it works, data produced per dependency, options,
dependency-type mapping, strengths and weaknesses. Then add a row to the
tables in `docs/decomposers/README.md` (including the networking and
inclusion-flag tables) and in the top-level `README.md`.

## Writing a system decomposer

A system decomposer reads what is *installed* on a filesystem rather than
what a project *declares*. OS package databases (rpm, deb, apk) produce a
flat inventory; installed language environments (Python site-packages,
Composer vendor directories) can produce a graph from the metadata each
distribution ships.

The interface adds one method and one contract:

```go
type SystemDecomposer interface {
    api.Decomposer
    ExtractFromFS(source fs.FS, opts *api.DecomposerOptions) (*sbom.NodeList, error)
}
```

- `source` is rooted at the system root. Look up paths relative to it:
  `var/lib/rpm/Packages`, not `/var/lib/rpm/Packages`. Never touch the host
  filesystem directly; the FS may be a squashed image or a tarball.
- **Return `(nil, nil)` when your database is not there.** Every system
  decomposer runs against every system, so absence is the common case and
  must not be an error. A database that exists but is empty returns an
  empty, non-nil NodeList.
- Implement `Extract` as a thin wrapper that opens `opts.WorkDir` with
  `os.DirFS` and calls `ExtractFromFS`, so the type also satisfies plain
  `api.Decomposer`.
- Honor `opts.IncludeFiles`: when set, emit a `Node_FILE` per installed
  file, hashed if the database records a digest, related to its package
  with `Edge_contains`. It is off by default because a full system holds
  hundreds of thousands of files.
- Packages become root nodes (`nl.AddRootNode`), since a flat inventory has
  no single parent. The unpacker that routed the filesystem (the image
  unpacker, for example) relates the whole list under its own node.
- Read `etc/os-release` through `system/internal/osrelease` to fill the
  purl namespace and the `distro` qualifier.

Register built-ins in `system.NewUnpacker`. Then add a row to the tables in
the decomposers README.

Test with `testing/fstest.MapFS`: build the filesystem in the test, run
`ExtractFromFS`, assert the graph. Include the "no database" case and check
it returns `(nil, nil)`. The apk and deb packages have examples of both unit
fixtures and Docker-backed conformance tests.

## Writing an artifact decomposer

An artifact decomposer reads what a *build* recorded in the thing it
produced: a Go executable carries its module list, and other formats
carry their own. The artifact unpacker owns the walk, the filtering, the
hashing and the file node; the decomposer owns recognizing and reading
one format.

```go
type Decomposer interface {
    api.Decomposer
    Name() string
    Matches(info fs.FileInfo, header []byte) bool
    ExtractArtifact(ra io.ReaderAt, path string, opts *api.DecomposerOptions) (*sbom.NodeList, error)
}
```

- `Name` is the short, stable name the decomposer is registered and
  switched by (`"gobinary"`). Export it as a constant.
- `Matches` gets the file metadata and its first `artifact.HeaderSize`
  bytes (64, fewer for a shorter file). Decide from magic numbers, never
  from the name or the exec bit. False positives are fine and cheap;
  the point is to skip the files that cannot possibly be yours without
  reading them.
- `ExtractArtifact` gets random access to the whole file. **Return
  `(nil, nil)` when the file turns out not to be one of yours**: the
  filter is coarse and every enabled decomposer sees every file that
  passes it, so disowning is the common case and must not be an error.
  Return an error only for a file that is yours and is broken.
- Root the list at the *package the artifact was built from*, not at the
  file. The unpacker creates the file node, hashes the file and relates
  your root to it with `generatedFrom`; the parent that found the file
  relates the file node to itself.
- Implement `Extract` as a thin wrapper that opens `opts.WorkDir` as the
  file and calls `ExtractArtifact`, so the type also satisfies plain
  `api.Decomposer`.
- Implement `api.SubjectDefaults` to say where you run by default. Think
  about each parent: a Go binary belongs in an image scan but has no
  business in a source tree scan. Leave it out entirely if you should
  run everywhere.
- **Reuse other decomposers through exported helpers, never by
  synthesizing their input.** `artifact/gobinary` builds a
  `golang.ModuleSet` and hands it to `golang.BuildNodeList`; it does not
  write a fake `go.mod` and call the source decomposer's `Extract`. If
  the helper you need is not exported, export it; that is a smaller
  change than faking a file, and the graph stays honest.

Register built-ins in `artifact.NewUnpacker`, keyed by `Name`. Then add
a row to the tables in the decomposers README.

Test with the test binary itself when your format is Go's, as the
gobinary tests do: every `go test` binary is a Go executable with build
information. Otherwise put a small real artifact under `testdata/`. Check
`Matches` on real headers and on noise, `ExtractArtifact` on a real file
and on a file that passes the filter but is not yours, and the graph
shape. A test through `artifact.NewUnpacker` with a `File` subject
covers the wrapping.

## Writing an unpacker and a subject

Do this when the *kind* of thing is new: there is no existing subject type
whose data your source can be expressed as. Before adding one, check whether
you can instead produce an existing subject and route it. A VM disk image,
for instance, may only need an unpacker that mounts it and routes the result
as a `system.Filesystem`.

### The subject

```go
// Package widget implements the unpacker that reads dependency data from
// widgets.
package widget

const SubjectType = "widget"

// Reference is the DecomposableSubject consumed by the widget unpacker.
type Reference struct {
    Path string
}

func (r *Reference) DecomposableType() string { return SubjectType }
```

Export the type-name constant so other unpackers and tests can refer to it.
Keep the subject a plain data carrier. If it needs behavior (opening a
reader, validating a reference string), add methods, but do not make the
subject do the extraction.

If several concrete subjects share a type, define an interface the unpacker
asserts to instead of a struct. `system.System` does this: `LocalSystem` and
`Filesystem` both return `"system"` and both expose `FileSystem() (fs.FS, error)`.
`artifact.Source` does the same for `File` and `Filesystem`.

If your subject hands out an `fs.FS`, make its files implement
`io.ReaderAt` where the backing store allows it. Some readers need random
access (`debug/buildinfo` on an executable, archive indexes at the end of
a file), and the artifact unpacker falls back to copying a file into
memory when its `fs.File` cannot seek. The image tarfs implements
`ReadAt` over its section reader for exactly this reason.

### The unpacker

```go
var _ api.Unpacker = (*Unpacker)(nil)

func init() {
    api.RegisterUnpacker(SubjectType, func() api.Unpacker { return NewUnpacker() })
}

type Options struct{ /* unpacker-level knobs */ }

var DefaultOptions = Options{}

func NewUnpacker() *Unpacker {
    return &Unpacker{
        Options:     DefaultOptions,
        decomposers: map[string]api.Decomposer{},
    }
}

type Unpacker struct {
    Options     Options
    decomposers map[string]api.Decomposer
}

func (u *Unpacker) Extract(ctx context.Context, subject api.DecomposableSubject) ([]*sbom.NodeList, error) {
    if subject == nil {
        return nil, fmt.Errorf("widget unpacker received a nil subject")
    }
    ref, ok := subject.(*Reference)
    if !ok {
        return nil, fmt.Errorf(
            "widget unpacker cannot process subject of type %q", subject.DecomposableType(),
        )
    }
    // Build DecomposerOptions from u.Options, run the decomposers, and
    // route any child subjects through api.UnpackerFor.
    ...
}

func (u *Unpacker) RegisterDecomposer(d api.Decomposer) {
    u.decomposers[fmt.Sprintf("%T", d)] = d
}

func (u *Unpacker) UnregisterDecomposer(d api.Decomposer) {
    delete(u.decomposers, fmt.Sprintf("%T", d))
}
```

Conventions the existing unpackers follow:

- Validate the subject first: nil check, then a type assertion with an
  error that names the subject type it received.
- Exported `Options` with a `DefaultOptions` value, so callers configure the
  unpacker by setting fields after `NewUnpacker`. Translate those into a
  fresh `DecomposerOptions` per decomposer call; decomposers never see the
  unpacker's options.
- Run every decomposer even when one fails. Collect errors with
  `errors.Join` and return them together with the lists that succeeded.
- When the unpacker discovers something another unpacker handles, wrap it
  in that unpacker's subject type and call `api.UnpackerFor`. Type-assert
  the returned unpacker only to pass options down (the image unpacker does
  this to forward `IncludeFiles`). If the child's decomposers carry
  `api.SubjectDefaults`, start from the child's `DefaultsFor(SubjectType)`
  and layer your caller's switches on top, so decomposers get a say in
  where they run and the caller gets the last word.
- Route the same data as several subjects when several kinds of child
  live in it, and decide the edge each child list gets from your node.
- Give the result structure. If your subject is itself a thing (an image, a
  release), emit a node for it with a purl and hashes and relate child
  lists under it with `RelateNodeListAtID(list, parentID, Edge_contains)`.
- An unpacker that only routes and has no decomposers of its own makes
  `RegisterDecomposer` and `UnregisterDecomposer` no-ops, as the image
  unpacker does.

### CLI

Add a command under `internal/cmd/` that parses its arguments into the
subject, builds the unpacker, sets options from flags and calls `Extract`.
Reuse the shared option sets in `optionsets.go` for output format and file
inclusion so the new command renders exactly like the others. The command
should do nothing else: all logic belongs in the unpacker.

## Checklist before opening a pull request

- [ ] SPDX header on every new file.
- [ ] Compile-time interface assertions (`var _ api.Decomposer = ...`).
- [ ] Pure Go; no shelling out to ecosystem tooling.
- [ ] Network use gated on `opts.Networking`; local data alone produces a graph.
- [ ] Root node carries `opts.Version` and `opts.CommitHash` (source decomposers).
- [ ] `(nil, nil)` when the database is absent (system decomposers) or the file is not yours (artifact decomposers).
- [ ] `api.SubjectDefaults` answered honestly for every parent kind (artifact decomposers).
- [ ] Files from a new `fs.FS` subject implement `io.ReaderAt` when they can.
- [ ] Every package node has a spec-conformant purl.
- [ ] Edge types match the inclusion flags.
- [ ] Registered in the right `NewUnpacker`, or in the registry from `init()`.
- [ ] Unit tests on fixtures under `testdata/`, `t.Parallel()`, Windows-safe file names.
- [ ] `go build ./... && go test ./... && golangci-lint run` pass.
- [ ] A page under `docs/decomposers/` and rows in both READMEs.

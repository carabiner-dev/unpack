# GitHub Actions Decomposer

**Location:** `source/githubactions/`

Reads what the [GitHub Actions](https://docs.github.com/actions)
workflows of a repository run that is not the repository's own: the
actions their steps use, the reusable workflows their jobs call, and the
container images their jobs and services run in. These are what builds,
tests and releases the project, and each is code someone else controls
running with the repository's secrets.

The decomposer is off by default and runs when asked for:

```bash
unpack extract --enable githubactions /path/to/repository
unpack ls --enable githubactions /path/to/repository
```

It is off because workflows are not what the project is built from. An
inventory of a project's dependencies is not asking for its CI, and a
repository that had one codebase would have two.

## How it works

1. `FindCodeBases` finds the directories that hold a
   `.github/workflows` with a YAML file in it. The codebase is the
   repository, not the directory of the workflows.
2. Every `.yml` and `.yaml` file of the directory is read. One that is
   not valid YAML is left out with a warning; the others are still read.
3. These keys are read from each workflow:

   | Key | What it is |
   |-----|------------|
   | `jobs.<id>.steps[].uses` | An action, `owner/repo[/path]@ref`, or an image, `docker://image:tag` |
   | `jobs.<id>.uses` | A reusable workflow, `owner/repo/.github/workflows/file.yml@ref` |
   | `jobs.<id>.container`, `.container.image` | The image a job runs in |
   | `jobs.<id>.services.<id>`, `.image` | The image of a service |

4. The repository's own actions the steps use, `./path`, are followed;
   see [Local actions](#local-actions).
5. Each distinct reference is one node, a `buildDependency` of the
   repository, with every place it is used on it. The same action at two
   refs is two nodes.

**Expressions** are left out, `${{ matrix.image }}`: the value is only
known when the workflow runs.

### Local actions

A step may use an action of the repository itself, `uses: ./path`. Such
an action is the repository's own code and is no node. What it runs
from elsewhere is, so its metadata file, `action.yml` or `action.yaml`
at that path, is read:

| Key | What it is |
|-----|------------|
| `runs.steps[].uses` | The steps of a composite action, read like a workflow's |
| `runs.image` | The image of a Docker action, when it is pulled: `docker://image:tag` |

A composite action may use other local actions, which are read in turn,
each once however many use it. A path is relative to the root of the
repository, and one that leads out of it is not followed. A reference
found this way says where: its `githubactions:used-in` names the
action's file.

A Docker action built from a `Dockerfile` beside it names nothing here:
its base image is in the Dockerfile, which is not read. A JavaScript
action runs code of the repository and names nothing either.

A reusable workflow of the repository,
`uses: ./.github/workflows/file.yml`, needs no following: it is one of
the workflow files, and is read with them.

GitHub is not asked anything: a ref is reported as written and is not
resolved to a commit.

## Data produced

### Actions and reusable workflows

| Field | Source | Notes |
|-------|--------|-------|
| Name | the reference | `owner/repo`, with the path of an action that is not at the root of its repository: `github/codeql-action/init` |
| Version | the ref | A tag, a branch or a commit, as written |
| PURL | computed | `pkg:github/{owner}/{repo}@{ref}`, with the path as the subpath: `pkg:github/github/codeql-action@v3#init` |
| Supplier | the owner | Whoever controls the repository, with its GitHub URL, as an organization |
| Repository | computed | `ExternalReference_VCS`, with the commit as its SHA-1 when the reference is pinned to one |

### Images

| Field | Source | Notes |
|-------|--------|-------|
| Name | the reference | The repository as written: `node`, `ghcr.io/owner/image` |
| Version | the reference | The digest when there is one, which names the content; the tag otherwise; none for a bare name |
| PURL | computed | `pkg:docker/{namespace}/{name}@{version}`, with `repository_url` for a registry other than the default and `tag` when both a tag and a digest are written |
| Hash (SHA-256) | the digest | When the image is referenced by digest |

### Properties

| Property | Meaning |
|----------|---------|
| `githubactions:kind` | `action`, `reusable-workflow` or `image` |
| `githubactions:pinned` | `true` for an action or workflow at a full commit SHA and an image by digest. `false` for a tag or a branch, which whoever controls the repository can move |
| `githubactions:used-in` | Each place it is used, as `file:line` |
| `githubactions:comment` | The comment on the line of the reference |

The comment is there for a convention: a reference pinned to a commit
usually says which version the commit is.

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

The version of that node is the commit, and `v4.1.1` is its comment. It
is what a person, or a bot, wrote; nothing checks that the commit is
that version.

## Dependency types

The inclusion flags are no-ops. Everything this decomposer reads is a
build dependency, and running it is asking for them: `--include-build`
is not needed.

## Generation context

`source`. The workflow files are read as they stand in the source tree.
See [Generation context](README.md#generation-context).

## Networking

None.

## Strengths

- **A part of the supply chain most inventories leave out.**
- **Says what is pinned.** A reader can list the references a third
  party can change under the repository.
- **Every use is located**, by file and line.

## Weaknesses

- **Refs are not resolved.** `actions/checkout@v4` is reported as `v4`,
  not as the commit the tag points at today.
- **Only what the workflows name.** What an action runs in turn, the
  actions a composite action uses or the image a Docker action builds,
  is in that action's repository.
- **A local Docker action's Dockerfile is not read**, so the base image
  it builds from is not listed.
- **Expressions are skipped**, so an image or action chosen from a
  matrix is not listed.
- **Tools installed by scripts are not seen**: a `run: curl … | sh` step
  is a dependency this cannot read.
- **Only GitHub Actions.** GitLab CI, CircleCI and the rest are not
  read.

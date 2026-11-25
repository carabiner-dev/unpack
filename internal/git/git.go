// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/mod/semver"
)

func getHeadHash(repo *git.Repository) (string, error) {
	headRef, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("reading head from repo: %w", err)
	}
	return headRef.Hash().String(), nil
}

// RepoVersion returns a version of the commit the repository at path is at,
// relative to the most recent tag in its history (see nearestTag), and the
// commit hash. The version is the tag itself at the tagged commit, empty
// without a tag in the history, and otherwise the tag, a separator, the
// number of newer commits and the abbreviated hash, like v1.0.1-2+2bce182a.
func RepoVersion(path string) (tag, commit string, err error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", "", fmt.Errorf("opening repository: %w", err)
	}

	headHash, err := getHeadHash(repo)
	if err != nil {
		return "", "", fmt.Errorf("reading head hash: %w", err)
	}

	// The version is relative to the nearest tag in the history of HEAD.
	// A tag on another branch says nothing about this commit, even when
	// it is the most recent one in the repository.
	lastTag, num, err := nearestTag(repo, plumbing.NewHash(headHash))
	if err != nil {
		return "", "", fmt.Errorf("finding the nearest tag: %w", err)
	}

	// If there is no tag, then dont, try to compute a version.
	// We just return the commit
	if lastTag == "" {
		return "", headHash, nil
	}

	if num == 0 {
		return lastTag, headHash, nil
	}

	// If we're not a the tag then we sinthesize the version
	sep := "-"
	if strings.Contains(lastTag, "-") {
		sep = "."
	}
	version := lastTag + fmt.Sprintf("%s%d+%s", sep, num, headHash[0:8])
	return version, headHash, nil
}

// Revision describes the commit a repository is at, with what its history
// says about it. It carries facts and no version: how they make one is up
// to whoever names the code, and ecosystems differ (see RepoVersion for
// the generic form).
type Revision struct {
	// Commit is the hash of the commit.
	Commit string

	// Time is when it was committed, in UTC.
	Time time.Time

	// Tags are the tags on the commit itself, sorted.
	Tags []string

	// AncestorTags are the tags on the commits it descends from, sorted.
	// A tag on a commit that is not in its history, on another branch,
	// is in neither list.
	AncestorTags []string
}

// HeadRevision reads the commit a repository's HEAD is at.
func HeadRevision(path string) (*Revision, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository: %w", err)
	}

	headRef, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("reading head from repo: %w", err)
	}
	head, err := repo.CommitObject(headRef.Hash())
	if err != nil {
		return nil, fmt.Errorf("reading head commit: %w", err)
	}

	revision := &Revision{
		Commit: head.Hash.String(),
		Time:   head.Committer.When.UTC(),
	}

	tagged, err := tagsByCommit(repo)
	if err != nil {
		return nil, err
	}
	if len(tagged) == 0 {
		return revision, nil
	}

	revision.Tags = tagged[head.Hash]
	delete(tagged, head.Hash)

	// The history is walked once, picking up the tags as their commits
	// come by, and no further than the last of them.
	err = walkHistory(repo, head.Hash, func(c *object.Commit) bool {
		if names, ok := tagged[c.Hash]; ok {
			revision.AncestorTags = append(revision.AncestorTags, names...)
			delete(tagged, c.Hash)
		}
		return len(tagged) > 0
	})
	if err != nil {
		return nil, fmt.Errorf("iterating history: %w", err)
	}

	sort.Strings(revision.Tags)
	sort.Strings(revision.AncestorTags)
	return revision, nil
}

// tagsByCommit returns the names of the tags of the repository by the
// commit they point at.
func tagsByCommit(repo *git.Repository) (map[plumbing.Hash][]string, error) {
	tagRefs, err := repo.Tags()
	if err != nil {
		return nil, fmt.Errorf("reading tags: %w", err)
	}
	tagged := map[plumbing.Hash][]string{}
	err = tagRefs.ForEach(func(tagRef *plumbing.Reference) error {
		// A tag may point at something that is not a commit, or at one
		// the repository does not hold: it names no version of the code.
		hash, err := repo.ResolveRevision(plumbing.Revision(tagRef.Name().String()))
		if err != nil {
			return nil //nolint:nilerr // deliberate: skip what does not resolve
		}
		tagged[*hash] = append(tagged[*hash], tagRef.Name().Short())
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading tags: %w", err)
	}
	return tagged, nil
}

// nearestTag returns the most recent tag in the history of head and how
// many commits of that history are newer than its commit. The history is
// walked by commit time, so a tag that came in through a merge counts as
// well as one on the first-parent line. The most recent tagged commit wins,
// even over a higher version further back. This is simpler than git
// describe, which weighs several tags and counts the commits only head
// has. They differ after merges: when an older release branch is merged
// into main after a newer tag, this picks the release branch tag, git
// describe the newer one, and commits older than the tag on a branch merged
// after it count for git describe, not here. Of several tags on a commit,
// the highest semantic version wins, then the name. It returns no tag when
// none is in the history.
func nearestTag(repo *git.Repository, head plumbing.Hash) (tag string, distance int, err error) {
	tagged, err := tagsByCommit(repo)
	if err != nil {
		return "", 0, err
	}
	if len(tagged) == 0 {
		return "", 0, nil
	}

	err = walkHistory(repo, head, func(c *object.Commit) bool {
		if names, ok := tagged[c.Hash]; ok {
			tag = highestTag(names)
			return false
		}
		distance++
		return true
	})
	if err != nil {
		return "", 0, fmt.Errorf("iterating history: %w", err)
	}
	if tag == "" {
		return "", 0, nil
	}
	return tag, distance, nil
}

// walkHistory calls visit with head and the commits of its history, the
// most recently committed first, until visit returns false. Like git, it
// treats the commits at the boundary of a shallow clone as having no
// parents, whether their parents are on disk or not. go-git's iterator by
// commit time reads the parents of a commit before returning it, which
// fails on a shallow clone, hence the walk here.
func walkHistory(repo *git.Repository, head plumbing.Hash, visit func(*object.Commit) bool) error {
	shallowList, err := repo.Storer.Shallow()
	if err != nil {
		return fmt.Errorf("reading shallow commits: %w", err)
	}
	shallow := map[plumbing.Hash]bool{}
	for _, hash := range shallowList {
		shallow[hash] = true
	}

	start, err := repo.CommitObject(head)
	if err != nil {
		return fmt.Errorf("reading commit %s: %w", head, err)
	}
	queue := &commitsByTime{start}
	seen := map[plumbing.Hash]bool{head: true}
	for queue.Len() > 0 {
		commit, ok := heap.Pop(queue).(*object.Commit)
		if !ok {
			return errors.New("not a commit")
		}
		if !visit(commit) {
			return nil
		}
		if shallow[commit.Hash] {
			continue
		}
		for _, parent := range commit.ParentHashes {
			if seen[parent] {
				continue
			}
			seen[parent] = true
			parentCommit, err := repo.CommitObject(parent)
			if err != nil {
				return fmt.Errorf("reading commit %s: %w", parent, err)
			}
			heap.Push(queue, parentCommit)
		}
	}
	return nil
}

// commitsByTime is a heap of commits, the most recently committed first.
type commitsByTime []*object.Commit

func (c *commitsByTime) Len() int { return len(*c) }

func (c *commitsByTime) Less(i, j int) bool {
	a, b := (*c)[i], (*c)[j]
	if !a.Committer.When.Equal(b.Committer.When) {
		return a.Committer.When.After(b.Committer.When)
	}
	return bytes.Compare(a.Hash[:], b.Hash[:]) < 0
}

func (c *commitsByTime) Swap(i, j int) { (*c)[i], (*c)[j] = (*c)[j], (*c)[i] }

func (c *commitsByTime) Push(x any) {
	if commit, ok := x.(*object.Commit); ok {
		*c = append(*c, commit)
	}
}

func (c *commitsByTime) Pop() any {
	old := *c
	commit := old[len(old)-1]
	*c = old[:len(old)-1]
	return commit
}

// withV adds the v prefix semver expects to tags without one, like 1.2.0.
func withV(tag string) string {
	if strings.HasPrefix(tag, "v") {
		return tag
	}
	return "v" + tag
}

// highestTag returns the highest semantic version of the tags, with or
// without a v prefix, or the last name in sort order when none or several
// equal ones are.
func highestTag(tags []string) string {
	return slices.MaxFunc(tags, func(a, b string) int {
		if c := semver.Compare(withV(a), withV(b)); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
}

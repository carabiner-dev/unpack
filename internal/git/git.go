// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func getHeadHash(repo *git.Repository) (string, error) {
	headRef, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("reading head from repo: %w", err)
	}
	return headRef.Hash().String(), nil
}

// RepoVersion
func RepoVersion(path string) (tag, commit string, err error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", "", fmt.Errorf("opening repository: %w", err)
	}

	headHash, err := getHeadHash(repo)
	if err != nil {
		return "", "", fmt.Errorf("reading head hash: %w", err)
	}

	// Get the latest tag
	lastTag, _, err := getLatestTagFromRepository(repo)
	if err != nil {
		return "", "", fmt.Errorf("reading latest tag: %w", err)
	}

	// If there is no tag, then dont, try to compute a version.
	// We just return the commit
	if lastTag == "" {
		return "", headHash, nil
	}

	num, err := getCommitsFromTag(repo, lastTag)
	if err != nil {
		return "", "", fmt.Errorf("finding commits from tag: %w", err)
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
	if len(tagged) == 0 {
		return revision, nil
	}

	revision.Tags = tagged[head.Hash]
	delete(tagged, head.Hash)

	// The history is walked once, picking up the tags as their commits
	// come by, and no further than the last of them.
	if len(tagged) > 0 {
		commits, err := repo.Log(&git.LogOptions{From: head.Hash})
		if err != nil {
			return nil, fmt.Errorf("creating commit iterator: %w", err)
		}
		errDone := errors.New("every tag found")
		err = commits.ForEach(func(c *object.Commit) error {
			if names, ok := tagged[c.Hash]; ok {
				revision.AncestorTags = append(revision.AncestorTags, names...)
				delete(tagged, c.Hash)
				if len(tagged) == 0 {
					return errDone
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, errDone) {
			return nil, fmt.Errorf("iterating history: %w", err)
		}
	}

	sort.Strings(revision.Tags)
	sort.Strings(revision.AncestorTags)
	return revision, nil
}

func GetLatestTag(path string) (tag, commit string, err error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", "", fmt.Errorf("opening repository: %w", err)
	}

	tag, ocommit, err := getLatestTagFromRepository(repo)
	if err != nil {
		return "", "", err
	}

	return tag, ocommit.Hash.String(), nil
}

// getCommitsFromTag returns the number of commits HEAD is from a tag
func getCommitsFromTag(repo *git.Repository, tagName string) (int, error) {
	headRef, err := repo.Head()
	if err != nil {
		return 0, fmt.Errorf("reading head from repo: %w", err)
	}

	tagRef, err := repo.Tag(tagName)
	if err != nil {
		return 0, fmt.Errorf("finding tag %q: %w", tagName, err)
	}

	tagCommitHash, err := repo.ResolveRevision(plumbing.Revision(tagRef.Name().String()))
	if err != nil {
		return 0, fmt.Errorf("resolving revision")
	}

	tagCommit, err := repo.CommitObject(*tagCommitHash)
	if err != nil {
		return 0, fmt.Errorf("finding tagged commit: %w", err)
	}

	// read the commit history backwards
	cIter, err := repo.Log(&git.LogOptions{From: headRef.Hash()})
	if err != nil {
		return 0, fmt.Errorf("creating commit iterator: %w", err)
	}

	i := 0
	found := false
	err = cIter.ForEach(func(c *object.Commit) error {
		if c.Hash.String() == tagCommit.Hash.String() {
			found = true
			return git.ErrTagExists
		}
		i++
		return nil
	})
	if err != nil && !errors.Is(err, git.ErrTagExists) {
		return 0, fmt.Errorf("iterating history: %w", err)
	}
	if !found {
		return 0, fmt.Errorf("tag not found in history")
	}
	return i, nil
}

func getLatestTagFromRepository(repo *git.Repository) (string, *object.Commit, error) {
	tagRefs, err := repo.Tags()
	if err != nil {
		return "", nil, err
	}

	var latestTagCommit *object.Commit
	var latestTagName string

	err = tagRefs.ForEach(func(tagRef *plumbing.Reference) error {
		revision := plumbing.Revision(tagRef.Name().String())
		tagCommitHash, err := repo.ResolveRevision(revision)
		if err != nil {
			return err
		}

		commit, err := repo.CommitObject(*tagCommitHash)
		if err != nil {
			return err
		}

		if latestTagCommit == nil {
			latestTagCommit = commit
			latestTagName = tagRef.Name().String()
		}

		if commit.Committer.When.After(latestTagCommit.Committer.When) {
			latestTagCommit = commit
			latestTagName = tagRef.Name().String()
		}

		return nil
	})
	if err != nil {
		return "", nil, err
	}

	return strings.TrimPrefix(latestTagName, "refs/tags/"), latestTagCommit, nil
}

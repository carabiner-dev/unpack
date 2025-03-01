// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"errors"
	"fmt"
	"strings"

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
func RepoVersion(path string) (tag string, commit string, err error) {
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

	num, err := getCommitsFromTag(repo, lastTag)
	if err != nil {
		return "", "", fmt.Errorf("finding commits from tag: %w", err)
	}

	if num == 0 {
		return lastTag, headHash, nil
	}

	// If we're not a the tag then we sinthesize the version
	return lastTag + fmt.Sprintf("-%d+%s", num, headHash[0:8]), headHash, nil
}

func GetLatestTag(path string) (string, string, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", "", fmt.Errorf("opening repository: %w", err)
	}

	tag, commit, err := getLatestTagFromRepository(repo)
	if err != nil {
		return "", "", err
	}

	return tag, commit.Hash.String(), nil
}

// getCommitsFromTag returns the number of commits HEAD is from a tag
func getCommitsFromTag(repo *git.Repository, tagName string) (int, error) {
	headRef, err := repo.Head()
	if err != nil {
		return 0, fmt.Errorf("reading head from repo: %w", err)
	}

	tagRef, err := repo.Tag(tagName)
	if err != nil {
		return 0, fmt.Errorf("finding tag: %w", err)
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

	var i = 0
	var found = false
	err = cIter.ForEach(func(c *object.Commit) error {
		fmt.Println(c.Hash.String() + " vs " + tagCommit.Hash.String())

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

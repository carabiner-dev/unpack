package git

import (
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/tar"
)

func TestGetLatestTagFromRepository(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	require.NoError(t, tar.Extract("testdata/tagged-repo.tar.gz", tmp))

	t.Run("last-tag", func(t *testing.T) {
		t.Parallel()

		repo, err := git.PlainOpen(tmp)
		require.NoError(t, err)

		tag, commit, err := getLatestTagFromRepository(repo)
		require.NoError(t, err)
		require.Equal(t, "v1.0.1", tag)
		require.Equal(t, "3449b21756d4f8981b44f7efd4769c1b61785c29", commit.Hash.String())
	})

	t.Run("history", func(t *testing.T) {
		t.Parallel()

		repo, err := git.PlainOpen(tmp)
		require.NoError(t, err)

		num, err := getCommitsFromTag(repo, "v1.0.1")
		require.NoError(t, err)
		require.Equal(t, 1, num)

		num, err = getCommitsFromTag(repo, "v1.0.0")
		require.NoError(t, err)
		require.Equal(t, 3, num)
	})

	t.Run("head-hash", func(t *testing.T) {
		t.Parallel()

		repo, err := git.PlainOpen(tmp)
		require.NoError(t, err)

		jach, err := getHeadHash(repo)
		require.NoError(t, err)
		require.Equal(t, "2bce182a96aa594f7f84858a9de52f7f44fdba17", jach)
	})

	t.Run("version", func(t *testing.T) {
		t.Parallel()

		version, hash, err := RepoVersion(tmp)
		require.NoError(t, err)

		require.Equal(t, "v1.0.1-1+2bce182a", version)
		require.Equal(t, "2bce182a96aa594f7f84858a9de52f7f44fdba17", hash)
	})
}

func TestHeadRevision(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	require.NoError(t, tar.Extract("testdata/tagged-repo.tar.gz", tmp))

	revision, err := HeadRevision(tmp)
	require.NoError(t, err)

	require.Equal(t, "2bce182a96aa594f7f84858a9de52f7f44fdba17", revision.Commit)

	// The commit time is the committer's, in UTC whatever zone it was
	// committed in.
	repo, err := git.PlainOpen(tmp)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	commit, err := repo.CommitObject(head.Hash())
	require.NoError(t, err)
	require.False(t, revision.Time.IsZero())
	require.True(t, revision.Time.Equal(commit.Committer.When))
	require.Equal(t, time.UTC, revision.Time.Location())

	// HEAD is one commit past v1.0.1 and three past v1.0.0: neither tag
	// is on it, both are in its history.
	require.Empty(t, revision.Tags)
	require.Equal(t, []string{"v1.0.0", "v1.0.1"}, revision.AncestorTags)
}

func TestHeadRevisionAtTagAndOffBranch(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	require.NoError(t, tar.Extract("testdata/tagged-repo.tar.gz", tmp))

	repo, err := git.PlainOpen(tmp)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)

	// Move HEAD back onto the commit v1.0.1 tags: the tag is on the
	// commit, the earlier one in its history, and nothing else.
	tagged, err := repo.ResolveRevision("refs/tags/v1.0.1")
	require.NoError(t, err)
	require.NoError(t, worktree.Checkout(&git.CheckoutOptions{Hash: *tagged, Force: true}))

	revision, err := HeadRevision(tmp)
	require.NoError(t, err)
	require.Equal(t, tagged.String(), revision.Commit)
	require.Equal(t, []string{"v1.0.1"}, revision.Tags)
	require.Equal(t, []string{"v1.0.0"}, revision.AncestorTags)

	// And back onto the one v1.0.0 tags: v1.0.1 is ahead of it, not in
	// its history.
	first, err := repo.ResolveRevision("refs/tags/v1.0.0")
	require.NoError(t, err)
	require.NoError(t, worktree.Checkout(&git.CheckoutOptions{Hash: *first, Force: true}))

	revision, err = HeadRevision(tmp)
	require.NoError(t, err)
	require.Equal(t, []string{"v1.0.0"}, revision.Tags)
	require.Empty(t, revision.AncestorTags)
}

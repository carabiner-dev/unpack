package git

import (
	"testing"

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

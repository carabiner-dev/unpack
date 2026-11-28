package git

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/tar"
)

func TestRepoVersion(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	require.NoError(t, tar.Extract("testdata/tagged-repo.tar.gz", tmp))

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

// testRepo builds a repository commit by commit, each an hour after the
// first one, with explicit parents.
type testRepo struct {
	t        *testing.T
	dir      string
	repo     *git.Repository
	worktree *git.Worktree
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	return &testRepo{t: t, dir: dir, repo: repo, worktree: worktree}
}

func (r *testRepo) commit(hour int, parents ...plumbing.Hash) plumbing.Hash {
	r.t.Helper()
	sig := &object.Signature{
		Name: "test", Email: "test@example.com",
		When: time.Date(2026, 1, 1, hour, 0, 0, 0, time.UTC),
	}
	hash, err := r.worktree.Commit(fmt.Sprintf("commit %d", hour), &git.CommitOptions{
		AllowEmptyCommits: true, Author: sig, Committer: sig, Parents: parents,
	})
	require.NoError(r.t, err)
	return hash
}

func (r *testRepo) tag(name string, hash plumbing.Hash) {
	r.t.Helper()
	_, err := r.repo.CreateTag(name, hash, nil)
	require.NoError(r.t, err)
}

func (r *testRepo) version(head plumbing.Hash) string {
	r.t.Helper()
	require.NoError(r.t, r.worktree.Checkout(&git.CheckoutOptions{Hash: head, Force: true}))
	version, hash, err := RepoVersion(r.dir)
	require.NoError(r.t, err)
	require.Equal(r.t, head.String(), hash)
	return version
}

// shallow turns the repository into a shallow clone with its history
// ending at boundary: the commits behind it are removed.
func (r *testRepo) shallow(boundary plumbing.Hash, removed ...plumbing.Hash) {
	r.t.Helper()
	gitDir := filepath.Join(r.dir, ".git")
	require.NoError(r.t, os.WriteFile(filepath.Join(gitDir, "shallow"), []byte(boundary.String()+"\n"), 0o600))
	for _, hash := range removed {
		name := hash.String()
		require.NoError(r.t, os.Remove(filepath.Join(gitDir, "objects", name[:2], name[2:])))
	}
}

// The expected versions match git describe --tags on these histories,
// except where noted (see nearestTag).
func TestRepoVersionHistories(t *testing.T) {
	t.Parallel()

	t.Run("newer tag on another branch", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// A release branch forks at v1.0.0 and gets v0.9.1 after the
		// head of main, like a patch release cut after the latest build
		// of main.
		base := r.commit(1)
		r.tag("v1.0.0", base)
		head := r.commit(3, r.commit(2, base))
		r.tag("v0.9.1", r.commit(4, base))

		version := r.version(head)
		require.Equal(t, "v1.0.0-2+"+head.String()[:8], version)
	})

	t.Run("branch merged over a tag", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		base := r.commit(1)
		r.tag("v1.0.0", base)
		branch := r.commit(4, r.commit(3, r.commit(2, base)))
		head := r.commit(6, r.commit(5, base), branch)

		version := r.version(head)
		require.Equal(t, "v1.0.0-5+"+head.String()[:8], version)
	})

	t.Run("release branch tag merged back", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		base := r.commit(1)
		r.tag("v1.0.0", base)
		release := r.commit(2, base)
		r.tag("v1.0.1", release)
		merge := r.commit(5, r.commit(4, r.commit(3, base)), release)
		head := r.commit(6, merge)

		version := r.version(head)
		require.Equal(t, "v1.0.1-4+"+head.String()[:8], version)
	})

	t.Run("older commits merged after a tag", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// Commits 2 and 3 are older than v1.0.1 and merge after it: they
		// are in the history of HEAD, but only newer commits count here.
		// git describe --tags says v1.0.1-3.
		base := r.commit(1)
		r.tag("v1.0.0", base)
		branch := r.commit(3, r.commit(2, base))
		tagged := r.commit(4, base)
		r.tag("v1.0.1", tagged)
		head := r.commit(5, tagged, branch)

		require.Equal(t, "v1.0.1-1+"+head.String()[:8], r.version(head))
	})

	t.Run("shallow clone at a tag", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		first := r.commit(1)
		head := r.commit(2, first)
		r.tag("v1.1.0", head)
		r.shallow(head, first)

		require.Equal(t, "v1.1.0", r.version(head))
	})

	t.Run("shallow clone past a tag", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		first := r.commit(1)
		tagged := r.commit(2, first)
		r.tag("v1.1.0", tagged)
		head := r.commit(3, tagged)
		r.shallow(tagged, first)

		require.Equal(t, "v1.1.0-1+"+head.String()[:8], r.version(head))
	})

	t.Run("shallow clone with the tag on another branch", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// A CI checkout of depth 1 with the tags fetched: the walk has to
		// end at HEAD instead of reading its missing parent.
		first := r.commit(1)
		r.tag("v1.0.1", r.commit(2, first))
		head := r.commit(3, first)
		r.shallow(head, first)

		require.Empty(t, r.version(head))

		revision, err := HeadRevision(r.dir)
		require.NoError(t, err)
		require.Empty(t, revision.Tags)
		require.Empty(t, revision.AncestorTags)
	})

	t.Run("shallow commit with its parent on disk", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// Like git, a commit listed as shallow has no parents, even when
		// they are still there, as after shallowing a full clone.
		first := r.commit(1)
		r.tag("v0.1.0", first)
		head := r.commit(2, first)
		r.shallow(head)

		require.Empty(t, r.version(head))
	})

	t.Run("no tag in the history", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		base := r.commit(1)
		r.tag("v9.9.9", r.commit(2, base))
		head := r.commit(3, base)

		version := r.version(head)
		require.Empty(t, version)
	})
}

func TestHighestTag(t *testing.T) {
	t.Parallel()

	require.Equal(t, "v1.10.0", highestTag([]string{"v1.9.0", "v1.10.0", "v1.2.0"}))
	require.Equal(t, "v1.0.0", highestTag([]string{"v1.0.0-rc.1", "v1.0.0"}))
	require.Equal(t, "b", highestTag([]string{"b", "a"}))
	require.Equal(t, "1.10.0", highestTag([]string{"1.9.0", "1.10.0"}))
}

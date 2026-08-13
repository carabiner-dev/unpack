// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixture is a real environment: uv pip install --target of
// requests[socks] plus python-dotenv from git, with everything but the
// dist-info directories removed.
func readTestEnvironment(t *testing.T) []*InstalledDistribution {
	t.Helper()
	dists, err := FindDistributions(os.DirFS("testdata/sitepackages"))
	require.NoError(t, err)
	return dists
}

func distByName(t *testing.T, dists []*InstalledDistribution, name string) *InstalledDistribution {
	t.Helper()
	for _, dist := range dists {
		if dist.Name == name {
			return dist
		}
	}
	t.Fatalf("no distribution named %s", name)
	return nil
}

func TestFindDistributions(t *testing.T) {
	t.Parallel()

	dists := readTestEnvironment(t)
	require.Len(t, dists, 7)

	// Sorted by normalized name, however the directory spells it:
	// PySocks-1.7.1.dist-info reads as pysocks.
	names := make([]string, 0, len(dists))
	for _, dist := range dists {
		names = append(names, dist.Name)
	}
	require.Equal(t, []string{
		"certifi", "charset-normalizer", "idna", "pysocks",
		"python-dotenv", "requests", "urllib3",
	}, names)
}

func TestReadDistribution(t *testing.T) {
	t.Parallel()

	dists := readTestEnvironment(t)
	requests := distByName(t, dists, "requests")

	require.Equal(t, "2.34.2", requests.Version)
	require.Equal(t, "Python HTTP for Humans.", requests.Summary)
	require.NotEmpty(t, requests.RequiresPython)
	require.Equal(t, "uv", requests.Installer)

	// The declared dependencies, raw PEP 508: the socks extra among them.
	require.NotEmpty(t, requests.RequiresDist)
	sawSocks := false
	for _, line := range requests.RequiresDist {
		req, err := parseRequirement(line)
		require.NoError(t, err, "requires-dist %q", line)
		if req.Name == "pysocks" {
			sawSocks = true
			require.Contains(t, req.Marker, "extra")
		}
	}
	require.True(t, sawSocks)

	// The RECORD's files, hashed in urlsafe base64.
	require.NotEmpty(t, requests.Files)
	hashed := 0
	for _, file := range requests.Files {
		if file.Algorithm != "" {
			hashed++
			require.Equal(t, "sha256", file.Algorithm)
			require.NotEmpty(t, file.Digest)
			require.NotContains(t, file.Digest, "=", "RECORD digests are unpadded")
		}
	}
	require.NotZero(t, hashed)
}

// TestDistributionLicenses runs the shared triage over the real metadata:
// the fixture set covers all three tiers.
func TestDistributionLicenses(t *testing.T) {
	t.Parallel()

	dists := readTestEnvironment(t)
	for name, expected := range map[string][]string{
		"idna":     {"BSD-3-Clause"}, // a declared License-Expression
		"requests": {"Apache-2.0"},   // the free-text License field
		"urllib3":  {"MIT"},
	} {
		dist := distByName(t, dists, name)
		require.Equal(t, expected,
			licensesFromMetadata(dist.LicenseExpression, dist.License, dist.Classifiers),
			"licences of %s", name)
	}
}

// TestDistributionDirectURL covers PEP 610: a package installed from git
// knows its repository and commit.
func TestDistributionDirectURL(t *testing.T) {
	t.Parallel()

	dotenv := distByName(t, readTestEnvironment(t), "python-dotenv")
	require.NotNil(t, dotenv.DirectURL)
	require.Equal(t, "https://github.com/theskumar/python-dotenv", dotenv.DirectURL.URL)
	require.Equal(t, "git", dotenv.DirectURL.VCSInfo.VCS)
	require.Equal(t, "eaf2a9129ccec6febda0f741eb3bb852c3f947bd", dotenv.DirectURL.VCSInfo.CommitID)
	require.Equal(t, "v1.2.1", dotenv.DirectURL.VCSInfo.RequestedRevision)

	// An index install has no direct_url.
	require.Nil(t, distByName(t, readTestEnvironment(t), "idna").DirectURL)
}

func TestReadDistributionErrors(t *testing.T) {
	t.Parallel()

	// A dist-info without METADATA is not a distribution.
	_, err := ReadDistribution(os.DirFS("testdata"), "sitepackages")
	require.Error(t, err)

	// An environment with none is empty, not broken.
	dists, err := FindDistributions(os.DirFS("testdata/simple"))
	require.NoError(t, err)
	require.Empty(t, dists)
}

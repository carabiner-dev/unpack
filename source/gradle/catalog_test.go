// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gradle

import (
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const catalogBuild = "testdata/catalog"

func TestParseCatalog(t *testing.T) {
	t.Parallel()
	catalog, err := ReadCatalog(filepath.Join(catalogBuild, CatalogFile))
	require.NoError(t, err)

	libraries := map[string]*CatalogLibrary{}
	for _, library := range catalog.Libraries {
		libraries[library.Alias] = library
	}
	// The bundle adds none, and what is no library is passed over.
	require.Len(t, libraries, 11)

	for alias, expected := range map[string]CatalogLibrary{
		"guava":            {Group: "com.google.guava", Name: "guava", Version: "33.2.0-jre"},
		"jackson-databind": {Group: "com.fasterxml.jackson.core", Name: "jackson-databind", Version: "2.17.1"},
		"jackson-core":     {Group: "com.fasterxml.jackson.core", Name: "jackson-core", Version: "2.17.1"},
		"okhttp":           {Group: "com.squareup.okhttp3", Name: "okhttp", Version: "4.12.0"},
		// A constraint that names one version is that version.
		"okio":  {Group: "com.squareup.okio", Name: "okio", Version: "3.9.0"},
		"slf4j": {Group: "org.slf4j", Name: "slf4j-api", Version: "1.7.36"},
		// A range, with a preference, is not one.
		"commons-lang3": {Group: "org.apache.commons", Name: "commons-lang3", Requested: "strictly [3.8, 4.0["},
		"dynamic":       {Group: "org.example", Name: "dynamic", Requested: "1.+"},
		// No version: a platform gives it one, somewhere in a script.
		"spring-web":    {Group: "org.springframework", Name: "spring-web"},
		"bom-managed":   {Group: "org.example", Name: "managed"},
		"undefined-ref": {Group: "org.example", Name: "undefined", Requested: "version.ref=nowhere"},
	} {
		expected.Alias = alias
		require.Equal(t, &expected, libraries[alias], alias)
	}

	plugins := map[string]*CatalogPlugin{}
	for _, plugin := range catalog.Plugins {
		plugins[plugin.Alias] = plugin
	}
	require.Equal(t, map[string]*CatalogPlugin{
		"kotlin-jvm": {Alias: "kotlin-jvm", ID: "org.jetbrains.kotlin.jvm", Version: "2.0.0"},
		"versions":   {Alias: "versions", ID: "com.github.ben-manes.versions", Version: "0.51.0"},
		"shorthand":  {Alias: "shorthand", ID: "com.diffplug.spotless", Version: "6.25.0"},
	}, plugins)

	catalog, err = ParseCatalog([]byte(""))
	require.NoError(t, err)
	require.Empty(t, catalog.Libraries)
	_, err = ParseCatalog([]byte("[libraries\n"))
	require.Error(t, err)
}

func TestExtractCatalog(t *testing.T) {
	t.Parallel()
	root, deps := extract(t, catalogBuild, &api.DecomposerOptions{})
	require.Equal(t, "catalog", root.GetName())
	require.Len(t, deps, 11, "the libraries; plugins wait for the build flag")

	guava := deps["guava"]
	require.Equal(t, sbom.Edge_dependsOn, guava.edge)
	require.Equal(t, "pkg:maven/com.google.guava/guava@33.2.0-jre", string(guava.node.Purl()))
	require.Equal(t, map[string][]string{
		PropertyReadFrom: {ReadFromCatalog},
		PropertyAlias:    {"guava"},
	}, properties(guava.node))

	commons := deps["commons-lang3"].node
	require.Empty(t, commons.GetVersion())
	require.Equal(t, "pkg:maven/org.apache.commons/commons-lang3", string(commons.Purl()))
	require.Equal(t, []string{"strictly [3.8, 4.0["}, properties(commons)[PropertyRequested])
	require.Empty(t, deps["spring-web"].node.GetVersion())

	// A library the build verifies has its hash, at the version asked
	// for.
	require.Equal(t, "b1050081b14bb7a3a7e55a4d3ef01b5dcfabc453b4573a4fc019767191d5f4e0",
		deps["okhttp"].node.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

	_, deps = extract(t, catalogBuild, &api.DecomposerOptions{IncludeBuild: true})
	require.Len(t, deps, 14)
	kotlin := deps["org.jetbrains.kotlin.jvm"]
	require.Equal(t, sbom.Edge_buildDependency, kotlin.edge)
	// The plugin's marker artifact, which is what Gradle resolves its
	// id to.
	require.Equal(t, "pkg:maven/org.jetbrains.kotlin.jvm/org.jetbrains.kotlin.jvm.gradle.plugin@2.0.0", string(kotlin.node.Purl()))
	require.Equal(t, map[string][]string{
		PropertyReadFrom: {ReadFromCatalog},
		PropertyAlias:    {"kotlin-jvm"},
		PropertyPluginID: {"org.jetbrains.kotlin.jvm"},
	}, properties(kotlin.node))
}

// TestLockfileOverCatalog checks a build that locks is read from its
// lockfile, whatever its catalog declares.
func TestLockfileOverCatalog(t *testing.T) {
	t.Parallel()
	_, deps := extract(t, appDir, &api.DecomposerOptions{IncludeDev: true, IncludeBuild: true})
	for name, dep := range deps {
		require.Empty(t, properties(dep.node)[PropertyReadFrom], name)
	}
}

func TestFindCodeBasesCatalog(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add(filepath.Join("build", "gradle"), "libs.versions.toml")
	index.Add(filepath.Join("build", "gradle"), "verification-metadata.xml")
	index.Add("locked", LockFile)
	index.Add(filepath.Join("locked", "gradle"), "libs.versions.toml")
	// A catalog by the name, somewhere that is no build's gradle
	// directory, and a gradle directory with no catalog.
	index.Add("docs", "libs.versions.toml")
	index.Add(filepath.Join("wrapper", "gradle"), "gradle-wrapper.properties")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"build", "locked"}, found)
}

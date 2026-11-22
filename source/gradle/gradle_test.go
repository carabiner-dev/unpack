// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gradle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/code"
)

const appDir = "testdata/project/app"

func TestParseLock(t *testing.T) {
	t.Parallel()
	lock, err := ReadLock(filepath.Join(appDir, LockFile))
	require.NoError(t, err)

	// Eight modules: the comments, the line that is nothing and the
	// coordinate with two parts are passed over.
	require.Len(t, lock.Modules, 8)
	require.Equal(t, []string{"signatures"}, lock.Empty)

	guava := lock.Modules[3]
	require.Equal(t, &Module{
		Group: "com.google.guava", Name: "guava", Version: "33.2.0-jre",
		// A space after the comma, as Gradle's own examples have.
		Configurations: []string{"runtimeClasspath", "testRuntimeClasspath"},
	}, guava)

	lock = ParseLock([]byte("# nothing locked\nempty=\n"))
	require.Empty(t, lock.Modules)
	require.Empty(t, lock.Empty)
}

func TestRole(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		configurations []string
		expected       Role
	}{
		"on the runtime classpath":       {[]string{"compileClasspath", "runtimeClasspath", "testRuntimeClasspath"}, RoleRuntime},
		"runtime only":                   {[]string{"runtimeClasspath"}, RoleRuntime},
		"compile only":                   {[]string{"compileClasspath", "testCompileClasspath"}, RoleCompileOnly},
		"an annotation processor":        {[]string{"annotationProcessor"}, RoleProcessor},
		"a processor also compiled with": {[]string{"annotationProcessor", "compileClasspath"}, RoleCompileOnly},
		"a processor of main and tests":  {[]string{"annotationProcessor", "testAnnotationProcessor"}, RoleProcessor},
		"the tests' own":                 {[]string{"testCompileClasspath", "testRuntimeClasspath"}, RoleTest},
		"a test processor":               {[]string{"testAnnotationProcessor"}, RoleTest},
		"a variant's runtime":            {[]string{"debugRuntimeClasspath", "releaseRuntimeClasspath"}, RoleRuntime},
		"a variant's tests":              {[]string{"debugUnitTestRuntimeClasspath", "debugAndroidTestCompileClasspath"}, RoleTest},
		"a variant's compile classpath":  {[]string{"releaseCompileClasspath"}, RoleCompileOnly},
		"a configuration of the build's": {[]string{"codegenClasspath"}, RoleRuntime},
		"the build script's":             {[]string{"classpath"}, RoleRuntime},
		"none":                           {nil, RoleRuntime},
	} {
		module := &Module{Configurations: tc.configurations}
		require.Equal(t, tc.expected, module.Role(), name)
	}
}

func TestVerification(t *testing.T) {
	t.Parallel()
	verification, err := ReadVerification("testdata/project/gradle/verification-metadata.xml")
	require.NoError(t, err)

	// The library's checksums, not its POM's or its metadata's, in lower
	// case; a signing key is no checksum.
	checksums, file := verification.Library(&Module{Group: "com.google.guava", Name: "guava", Version: "33.2.0-jre"})
	require.Equal(t, "guava-33.2.0-jre.jar", file)
	require.Equal(t, map[string]string{
		"sha256": "1f8e20b8e3f23de2d6e1f5b9e9c8e1e0a5a2b4d6f8a0c2e4f6a8b0c2d4e6f8a0",
		"sha512": "aa11",
	}, checksums)

	// An Android library.
	_, file = verification.Library(&Module{Group: "com.android.demo", Name: "feature", Version: "1.0.0"})
	require.Equal(t, "feature-1.0.0.aar", file)

	for name, module := range map[string]*Module{
		"only its POM is verified": {Group: "org.junit.jupiter", Name: "junit-jupiter-api", Version: "5.10.2"},
		"verified by signature":    {Group: "com.fasterxml.jackson.core", Name: "jackson-databind", Version: "2.17.1"},
		"another version":          {Group: "com.google.guava", Name: "guava", Version: "1.0"},
		"not in the file":          {Group: "org.example", Name: "none", Version: "1.0"},
	} {
		checksums, _ := verification.Library(module)
		require.Empty(t, checksums, name)
	}

	// No metadata at all is no checksums.
	var none *Verification
	checksums, _ = none.Library(&Module{Group: "a", Name: "b", Version: "1"})
	require.Empty(t, checksums)

	_, err = ParseVerification([]byte("<not xml"))
	require.Error(t, err)
}

func TestFindVerification(t *testing.T) {
	t.Parallel()
	// A project of a build finds the build's, above it.
	found := FindVerification(appDir)
	require.Equal(t, "verification-metadata.xml", filepath.Base(found))

	// Not above the repository the project is in.
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(outside, "gradle"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "gradle", "verification-metadata.xml"), []byte("<x/>"), 0o600))
	repo := filepath.Join(outside, "repo")
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "app"), 0o750))
	require.Empty(t, FindVerification(filepath.Join(repo, "app")))
}

type related struct {
	edge sbom.Edge_Type
	node *sbom.Node
}

func extract(t *testing.T, dir string, opts *api.DecomposerOptions) (root *sbom.Node, deps map[string]related) {
	t.Helper()
	opts.WorkDir = dir
	nl, err := New().Extract(opts)
	require.NoError(t, err)
	roots := nl.GetRootNodes()
	require.Len(t, roots, 1)

	byID := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		byID[node.GetId()] = node
	}
	deps = map[string]related{}
	for _, e := range nl.GetEdges() {
		require.Equal(t, roots[0].GetId(), e.GetFrom(), "the graph is flat")
		for _, to := range e.GetTo() {
			deps[byID[to].GetName()] = related{e.GetType(), byID[to]}
		}
	}
	require.Len(t, deps, len(byID)-1, "every module hangs from the root")
	return roots[0], deps
}

func properties(node *sbom.Node) map[string][]string {
	out := map[string][]string{}
	for _, property := range node.GetProperties() {
		out[property.GetName()] = append(out[property.GetName()], property.GetData())
	}
	return out
}

func TestExtract(t *testing.T) {
	t.Parallel()

	// By default: what ships with the project, and what it is compiled
	// against and something else provides.
	root, deps := extract(t, appDir, &api.DecomposerOptions{Version: "v1.0.0", CommitHash: "abc"})
	require.Equal(t, "app", root.GetName())
	require.Equal(t, "pkg:generic/app@v1.0.0", string(root.Purl()))
	require.Len(t, root.GetExternalReferences(), 1)

	edges := map[string]sbom.Edge_Type{}
	for name, dep := range deps {
		edges[name] = dep.edge
	}
	require.Equal(t, map[string]sbom.Edge_Type{
		"jackson-databind":    sbom.Edge_dependsOn,
		"guava":               sbom.Edge_dependsOn,
		"feature":             sbom.Edge_dependsOn,
		"codegen":             sbom.Edge_dependsOn,
		"jakarta.servlet-api": sbom.Edge_providedDependency,
		"lombok":              sbom.Edge_providedDependency,
	}, edges)

	guava := deps["guava"].node
	require.Equal(t, "33.2.0-jre", guava.GetVersion())
	require.Equal(t, "pkg:maven/com.google.guava/guava@33.2.0-jre", string(guava.Purl()))
	require.Equal(t, map[int32]string{
		int32(sbom.HashAlgorithm_SHA256): "1f8e20b8e3f23de2d6e1f5b9e9c8e1e0a5a2b4d6f8a0c2e4f6a8b0c2d4e6f8a0",
		int32(sbom.HashAlgorithm_SHA512): "aa11",
	}, guava.GetHashes())
	require.Equal(t, map[string][]string{
		PropertyConfiguration: {"runtimeClasspath", "testRuntimeClasspath"},
		PropertyVerifiedFile:  {"guava-33.2.0-jre.jar"},
	}, properties(guava), "also on the build script's classpath, and the project's own first")

	require.Empty(t, deps["jackson-databind"].node.GetHashes(), "verified by its signature alone")
	require.Equal(t, []string{"feature-1.0.0.aar"}, properties(deps["feature"].node)[PropertyVerifiedFile])

	// The tests' own, and what runs in the compiler or builds the
	// project, under their flags.
	_, deps = extract(t, appDir, &api.DecomposerOptions{IncludeDev: true})
	require.Len(t, deps, 7)
	require.Equal(t, sbom.Edge_devDependency, deps["junit-jupiter-api"].edge)

	_, deps = extract(t, appDir, &api.DecomposerOptions{IncludeBuild: true})
	require.Len(t, deps, 8)
	require.Equal(t, sbom.Edge_buildDependency, deps["mapstruct-processor"].edge)
	plugin := deps["gradle-versions-plugin"]
	require.Equal(t, sbom.Edge_buildDependency, plugin.edge)
	require.Equal(t, "pkg:maven/com.github.ben-manes/gradle-versions-plugin@0.51.0", string(plugin.node.Purl()))
	require.Equal(t, map[string][]string{
		PropertyConfiguration: {"classpath"},
		PropertyBuildscript:   {"true"},
	}, properties(plugin.node))
}

// TestExtractBuildscriptOnly checks a project that only locks its build
// script is read, and has nothing without the build flag.
func TestExtractBuildscriptOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, BuildscriptLockFile),
		[]byte("org.example:plugin:1.0=classpath\nempty=\n"), 0o600))

	_, deps := extract(t, dir, &api.DecomposerOptions{})
	require.Empty(t, deps)
	_, deps = extract(t, dir, &api.DecomposerOptions{IncludeBuild: true})
	require.Len(t, deps, 1)
	require.Empty(t, deps["plugin"].node.GetHashes(), "no verification metadata, no hashes")

	_, err := New().Extract(&api.DecomposerOptions{WorkDir: t.TempDir()})
	require.ErrorContains(t, err, "no gradle.lockfile")
}

func TestFindCodeBases(t *testing.T) {
	t.Parallel()
	index := code.PathIndex{}
	index.Add("build", LockFile)
	index.Add("build", BuildscriptLockFile)
	index.Add("build/app", LockFile)
	index.Add("build/plugins", BuildscriptLockFile)
	// A project that does not lock.
	index.Add("unlocked", "build.gradle.kts")

	found, err := New().FindCodeBases(&index)
	require.NoError(t, err)
	require.Equal(t, []string{"build", "build/app", "build/plugins"}, found)
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package jar

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBundleLicenses(t *testing.T) {
	t.Parallel()
	for header, expected := range map[string][]string{
		"https://www.apache.org/licenses/LICENSE-2.0.txt": {"Apache-2.0"},
		"Apache-2.0": {"Apache-2.0"},
		`Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"`: {"Apache-2.0"},
		"MIT, Apache-2.0":       {"MIT", "Apache-2.0"},
		"Apache-2.0,Apache-2.0": {"Apache-2.0"},
		`MIT;description="Free, as in speech";link=https://opensource.org/licenses/MIT`: {"MIT"},
		// A name nothing recognizes is passed on as written; a URL
		// nothing recognizes is not a license to pass on.
		"Example Commercial License":         {"Example Commercial License"},
		"https://example.com/our-terms.html": {},
		"":                                   {},
	} {
		require.Equal(t, expected, bundleLicenses(header), header)
	}
}

// pomXML is a POM as Maven embeds it, declaring what it is given.
func pomXML(group, artifact, body string) (name string, content []byte) {
	return "META-INF/maven/" + group + "/" + artifact + "/pom.xml",
		[]byte(`<project><modelVersion>4.0.0</modelVersion><groupId>` + group + `</groupId><artifactId>` + artifact +
			`</artifactId><version>1.0</version>` + body + `</project>`)
}

const (
	mitLicenses    = `<licenses><license><name>MIT License</name><url>https://opensource.org/licenses/MIT</url></license></licenses>`
	exampleOrg     = `<organization><name>Example Foundation</name></organization>`
	apacheManifest = "Bundle-License: https://www.apache.org/licenses/LICENSE-2.0.txt\n"
)

func TestArchiveLicense(t *testing.T) {
	t.Parallel()
	// The text of a license the classifier knows: this repository's own.
	apacheText, err := os.ReadFile("../../LICENSE.txt")
	require.NoError(t, err)

	propsName, props := pomProperties("org.example", "lib", "1.0")
	declaringName, declaring := pomXML("org.example", "lib", mitLicenses+exampleOrg)
	inheritingName, inheriting := pomXML("org.example", "lib", `<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1</version></parent>`)

	for name, tc := range map[string]struct {
		entries  map[string][]byte
		licenses []string
		source   string
		vendor   string
	}{
		"the POM declares it": {
			map[string][]byte{propsName: props, declaringName: declaring, "META-INF/MANIFEST.MF": []byte(apacheManifest), "META-INF/LICENSE": apacheText},
			[]string{"MIT"},
			LicenseFromPOM, "Example Foundation",
		},
		// The common case: the license is the parent's, which is not in
		// the archive, and the manifest says.
		"the POM inherits it, the manifest says": {
			map[string][]byte{propsName: props, inheritingName: inheriting, "META-INF/MANIFEST.MF": []byte(apacheManifest)},
			[]string{"Apache-2.0"},
			LicenseFromManifest, "",
		},
		"only a license file": {
			map[string][]byte{propsName: props, inheritingName: inheriting, "META-INF/LICENSE.txt": apacheText},
			[]string{"Apache-2.0"},
			LicenseFromFile, "",
		},
		"a license file at the root, and no Maven": {
			map[string][]byte{"LICENSE": apacheText, "A.class": []byte("x")},
			[]string{"Apache-2.0"},
			LicenseFromFile, "",
		},
		// The manifest's vendor is the archive's own word, and stands.
		"a vendor in the manifest": {
			map[string][]byte{propsName: props, declaringName: declaring, "META-INF/MANIFEST.MF": []byte("Implementation-Vendor: Example Inc\n")},
			[]string{"MIT"},
			LicenseFromPOM, "Example Inc",
		},
		"a license file nobody recognizes": {
			map[string][]byte{propsName: props, "META-INF/LICENSE": []byte("ask us first")}, nil, "", "",
		},
		"a license file deeper down is another package's": {
			map[string][]byte{propsName: props, "META-INF/licenses/other/LICENSE": apacheText}, nil, "", "",
		},
		"nothing says": {map[string][]byte{propsName: props}, nil, "", ""},
	} {
		archive := open(t, jar(t, tc.entries), "lib-1.0.jar")
		require.Equal(t, tc.licenses, archive.Identity.Licenses, name)
		require.Equal(t, tc.source, archive.Identity.LicenseSource, name)
		require.Equal(t, tc.vendor, archive.Identity.Vendor, name)
	}
}

// TestShadedLicenses checks each package unpacked into an archive takes
// the license its own POM declares, and that the archive's license file,
// which may be any of theirs, is not taken for the archive's.
func TestShadedLicenses(t *testing.T) {
	t.Parallel()
	apacheText, err := os.ReadFile("../../LICENSE.txt")
	require.NoError(t, err)

	toolProps, tool := pomProperties("org.example", "tool", "0.9")
	depProps, dep := pomProperties("org.example", "dep", "2.0")
	depPOMName, depPOM := pomXML("org.example", "dep", mitLicenses)
	otherProps, other := pomProperties("org.example", "other", "3.0")

	data := jar(t, map[string][]byte{
		toolProps: tool, depProps: dep, depPOMName: depPOM, otherProps: other, "META-INF/LICENSE": apacheText,
	})
	g := extract(t, data, "tool-0.9.jar")

	require.Empty(t, g.root.GetLicenses())
	require.Equal(t, []string{"MIT"}, g.nodes["dep"].GetLicenses())
	require.Equal(t, LicenseFromPOM, properties(g.nodes["dep"])[PropertyLicenseFrom])
	require.Empty(t, g.nodes["other"].GetLicenses())
	require.NotContains(t, properties(g.nodes["other"]), PropertyLicenseFrom)
}

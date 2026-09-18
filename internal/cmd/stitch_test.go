// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSBOMCommandAddSBOM enriches a shallow SBOM with a document describing
// one of its components.
func TestSBOMCommandAddSBOM(t *testing.T) {
	commandLineOpts.logLevel = "info"
	root := &cobra.Command{Use: "test"}
	addSBOM(root)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)

	// The sbom command writes to stdout directly; capture it.
	stdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	root.SetArgs([]string{
		"sbom", "-f", "spdx",
		"-p", filepath.Join("testdata", "stitch", "base.spdx.json"),
		"--add-sbom", filepath.Join("testdata", "stitch", "tool.spdx.json"),
	})
	runErr := root.Execute()
	os.Stdout = stdout
	require.NoError(t, w.Close())
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, runErr)

	doc := string(data)
	assert.Contains(t, doc, "pkg:generic/app@1.0.0")
	assert.Contains(t, doc, "pkg:generic/libfoo@2.0.0", "the supplement's dependencies came in under tool")
	assert.Contains(t, doc, "pkg:generic/libbar@3.1.0")
	assert.Contains(t, doc, "Apache-2.0", "the supplement's license landed on tool")
	assert.Contains(t, doc, "https://example.com/sboms/tool", "provenance points at the supplement")
	assert.Equal(t, 1, bytes.Count(data, []byte(`"name": "tool"`)), "tool is one package, not two")
}

// TestArtifactCommandAddSBOM describes the fixture binary by hash in a
// supplement and checks its data is stitched under the file.
func TestArtifactCommandAddSBOM(t *testing.T) {
	dir := artifactDir(t)
	bin, err := os.ReadFile(filepath.Join(dir, "tool"))
	require.NoError(t, err)
	sum := sha256.Sum256(bin)

	supplement := filepath.Join(t.TempDir(), "tool.spdx.json")
	data := fmt.Appendf(nil, `{
  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "tool",
  "documentNamespace": "https://example.com/sboms/fixture",
  "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {"SPDXID": "SPDXRef-tool", "name": "described-tool", "versionInfo": "7.7.7", "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "checksums": [{"algorithm": "SHA256", "checksumValue": %q}],
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:generic/described-tool@7.7.7"}]},
    {"SPDXID": "SPDXRef-extra", "name": "extra", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:generic/extra@1.0.0"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-tool", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-tool", "relatedSpdxElement": "SPDXRef-extra", "relationshipType": "DEPENDS_ON"}
  ]
}`, hex.EncodeToString(sum[:]))
	require.NoError(t, os.WriteFile(supplement, data, 0o600)) //nolint:gosec // a temp dir

	outPath := filepath.Join(t.TempDir(), "artifact.spdx.json")
	require.NoError(t, runArtifact(t,
		"-f", "spdx", "--networking", "disabled", "--add-sbom", supplement, "-o", outPath, filepath.Join(dir, "tool"),
	))
	data, err = os.ReadFile(outPath)
	require.NoError(t, err)
	doc := string(data)
	assert.Contains(t, doc, "pkg:golang/github.com/carabiner-dev/unpack", "the binary was still decomposed")
	assert.Contains(t, doc, "pkg:generic/described-tool@7.7.7", "and the supplement hangs under the file too")
	assert.Contains(t, doc, "pkg:generic/extra@1.0.0")
	assert.Contains(t, doc, "GENERATED_FROM")

	// A supplement path that does not exist fails validation.
	require.ErrorContains(t, runArtifact(t, "--add-sbom", "/nonexistent.json", filepath.Join(dir, "tool")), "loading supplemental SBOMs")
}

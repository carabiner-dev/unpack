// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// spdxDocument is a minimal SPDX 2.3 document describing one package. It
// is the payload every case below carries, bare or enveloped, so that the
// assertions can be identical no matter how it traveled.
const spdxDocument = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "enveloped-test",
  "documentNamespace": "https://carabiner.dev/test/enveloped",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: unpack-test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-hello",
      "name": "hello",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-hello",
      "relationshipType": "DESCRIBES"
    }
  ]
}`

const spdxPredicateType = "https://spdx.dev/Document"

// statement wraps a predicate in an in-toto statement.
func statement(t *testing.T, predicateType, predicate string) []byte {
	t.Helper()
	require.True(t, json.Valid([]byte(predicate)), "predicate is not valid JSON")
	return fmt.Appendf(nil, `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "hello", "digest": {"sha256": "%s"}}],
  "predicateType": %q,
  "predicate": %s
}`, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		predicateType, predicate)
}

// dsseEnvelope signs nothing: it wraps the statement in the DSSE
// structure with a placeholder signature, which is all the parser needs.
func dsseEnvelope(t *testing.T, stmt []byte) []byte {
	t.Helper()
	return fmt.Appendf(nil, `{
  "payloadType": "application/vnd.in-toto+json",
  "payload": %q,
  "signatures": [{"keyid": "", "sig": %q}]
}`, base64.StdEncoding.EncodeToString(stmt),
		base64.StdEncoding.EncodeToString([]byte("not-a-real-signature")))
}

// sigstoreBundle wraps a DSSE envelope in the sigstore bundle structure.
func sigstoreBundle(t *testing.T, stmt []byte) []byte {
	t.Helper()
	return fmt.Appendf(nil, `{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "dsseEnvelope": {
    "payloadType": "application/vnd.in-toto+json",
    "payload": %q,
    "signatures": [{"keyid": "", "sig": %q}]
  }
}`, base64.StdEncoding.EncodeToString(stmt),
		base64.StdEncoding.EncodeToString([]byte("not-a-real-signature")))
}

func TestExtract(t *testing.T) {
	t.Parallel()

	spdxStatement := statement(t, spdxPredicateType, spdxDocument)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"bare document", []byte(spdxDocument)},
		{"in-toto statement", spdxStatement},
		{"dsse envelope", dsseEnvelope(t, spdxStatement)},
		{"sigstore bundle", sigstoreBundle(t, spdxStatement)},
		{
			// The predicate type is what the producer wrote, not
			// something we get to insist on.
			"envelope with a nonstandard predicate type",
			dsseEnvelope(t, statement(t, "https://example.com/my-sbom/v1", spdxDocument)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nodelists, err := NewUnpacker().Extract(
				t.Context(), &Subject{Reader: bytes.NewReader(tc.data)},
			)
			require.NoError(t, err)
			require.Len(t, nodelists, 1)

			nodes := nodelists[0].GetNodes()
			require.Len(t, nodes, 1)
			require.Equal(t, "hello", nodes[0].GetName())
			require.Equal(t, "1.0.0", nodes[0].GetVersion())
		})
	}
}

func TestExtractErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		data    []byte
		mustSay string
	}{
		{
			// Nothing here is an envelope, so the report stays
			// protobom's: the data is simply not an SBOM.
			"plain json",
			[]byte(`{"hello": "world"}`),
			"unknown SBOM format",
		},
		{
			"not json at all",
			[]byte("hello world\n"),
			"unknown SBOM format",
		},
		{
			// Here we did open an envelope, and saying what it turned
			// out to hold beats saying the format was unreadable.
			"envelope holding something else",
			dsseEnvelope(t, statement(t, "https://slsa.dev/provenance/v1", `{"buildDefinition": {}}`)),
			errNoEnvelopedSBOM.Error(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewUnpacker().Extract(
				t.Context(), &Subject{Reader: bytes.NewReader(tc.data)},
			)
			require.ErrorContains(t, err, tc.mustSay)
		})
	}
}

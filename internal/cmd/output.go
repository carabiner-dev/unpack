// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	gintoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/generic"
	intoto "github.com/policylabs/collector/statement/intoto"
	"github.com/policylabs/signer"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/release-utils/version"
)

type bcloser struct {
	Buffer bytes.Buffer
}

func (bc *bcloser) Close() error {
	return nil
}

func (bc *bcloser) Write(d []byte) (int, error) {
	return bc.Buffer.Write(d)
}

// predicateTypeFor returns the in-toto predicate type naming what a document
// in this format is.
//
// SPDX 3 has one of its own. It is a different serialization of a different
// model, not a new version of the same document, so a consumer has to be able
// to tell from the statement whether it can read the predicate without first
// parsing it.
func predicateTypeFor(format formats.Format) (string, error) {
	switch {
	case format == formats.SPDX3JSON:
		return "https://spdx.dev/Document/v3", nil
	case format.Type() == formats.SPDXFORMAT:
		return "https://spdx.dev/Document", nil
	case format.Type() == formats.CDXFORMAT:
		return "https://cyclonedx.org/bom", nil
	default:
		return "", fmt.Errorf("unsupported format to attest: %s", format)
	}
}

// nodeLlistToAttestation writes the nodelist to an attestation
func nodeListToAttestation(wr io.WriteCloser, format formats.Format, nl *sbom.NodeList, opts ...documentOption) error {
	predicateType, err := predicateTypeFor(format)
	if err != nil {
		return err
	}

	// Create the new attestation
	att := intoto.NewStatement()
	att.PredicateType = attestation.PredicateType(predicateType)

	// Generate the subjects from the root nodes of the nodelist
	for _, n := range nl.GetRootNodes() {
		sub := gintoto.ResourceDescriptor{
			Digest: map[string]string{},
		}

		if n.GetHashes() != nil {
			for a, v := range n.GetHashes() {
				if _, ok := sbom.HashAlgorithm_name[a]; !ok {
					continue
				}
				sub.Digest[strings.ToLower(sbom.HashAlgorithm_name[a])] = v
			}
		}

		// If the subject still has no hashes, then it's a codebase. Use the commit hash
		if len(sub.GetDigest()) == 0 && n.GetExternalReferences() != nil {
			for _, ref := range n.GetExternalReferences() {
				if ref.GetType() == sbom.ExternalReference_VCS {
					for algo, h := range ref.GetHashes() {
						sub.Digest[strings.ToLower(sbom.HashAlgorithm_name[algo])] = h
					}
				}
			}
		}

		sub.DownloadLocation = n.GetUrlDownload()
		sub.Name = string(n.Purl())
		att.Subject = append(att.Subject, &sub)
	}

	// TODO(puerco): Drop the bcloser for a plain buffer once
	// https://github.com/protobom/protobom/pull/330 merges
	bc := bcloser{
		Buffer: bytes.Buffer{},
	}

	if err := nodeListToSbom(&bc, format, nl, opts...); err != nil {
		return fmt.Errorf("rendering SBOM to predicate: %w", err)
	}

	att.Predicate = &generic.Predicate{
		Type: attestation.PredicateType(predicateType),
		Data: bc.Buffer.Bytes(),
	}

	// Now render the attestation to the writer
	enc := json.NewEncoder(wr)
	enc.SetIndent("", "  ")
	if err := enc.Encode(att); err != nil {
		return fmt.Errorf("marshaling attestation: %w", err)
	}

	return nil
}

// nodeListToSignedAttestation creates an in-toto attestation from the nodelist
// and signs it into a sigstore bundle using the provided signer.
func nodeListToSignedAttestation(s *signer.Signer, wr io.WriteCloser, format formats.Format, nl *sbom.NodeList, opts ...documentOption) error {
	// First, render the attestation to a buffer
	buf := &bcloser{Buffer: bytes.Buffer{}}
	if err := nodeListToAttestation(buf, format, nl, opts...); err != nil {
		return fmt.Errorf("rendering attestation: %w", err)
	}

	// Sign the attestation statement into a sigstore bundle
	bndl, err := s.SignStatement(buf.Buffer.Bytes())
	if err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	// Write the signed artifact to the output
	if _, err := bndl.WriteTo(wr); err != nil {
		return fmt.Errorf("writing signed bundle: %w", err)
	}

	return nil
}

// documentOption sets something on the document a node list is written
// as, beyond what every document gets.
type documentOption func(*sbom.Document)

// withAuthors names the authors of the document.
func withAuthors(authors []*sbom.Person) documentOption {
	return func(doc *sbom.Document) {
		doc.Metadata.Authors = append(doc.Metadata.Authors, authors...)
	}
}

// The generation contexts a document is written in: at what point of the
// software's life it was made and so what there was to read. They are the
// SBOM types CISA defines, of which these are the two unpack makes.
const (
	// contextSource is a document made from a source tree and the
	// manifests and locks in it, before anything is built.
	contextSource = sbom.DocumentType_SOURCE

	// contextAnalyzed is a document made by taking apart something
	// already built: a binary, an image, the artifacts of a release.
	contextAnalyzed = sbom.DocumentType_ANALYZED
)

// contextComments say each context in words, for the formats that have no
// field to state it in.
var contextComments = map[sbom.DocumentType_SBOMType]string{
	contextSource:   "SBOM type: source. Generated from a source tree and the dependency manifests and lock files in it, before a build.",
	contextAnalyzed: "SBOM type: analyzed. Generated by analyzing an artifact after it was built.",
}

// withContext states the generation context of the document.
func withContext(generation sbom.DocumentType_SBOMType) documentOption {
	return func(doc *sbom.Document) {
		doc.Metadata.DocumentTypes = append(doc.Metadata.DocumentTypes, &sbom.DocumentType{Type: &generation})
	}
}

// commentContext writes the generation context into the document's comment
// for the formats that cannot state it otherwise. CycloneDX has lifecycle
// phases and SPDX 3 an SBOM type; SPDX 2 has neither, and a document that
// says nothing of how it was made is one a reader cannot weigh.
func commentContext(doc *sbom.Document, format formats.Format) {
	if format.Type() != formats.SPDXFORMAT || format == formats.SPDX3JSON || doc.GetMetadata().GetComment() != "" {
		return
	}
	for _, documentType := range doc.GetMetadata().GetDocumentTypes() {
		if comment, ok := contextComments[documentType.GetType()]; ok {
			doc.Metadata.Comment = comment
			return
		}
	}
}

func nodeListToSbom(wr io.WriteCloser, format formats.Format, nl *sbom.NodeList, opts ...documentOption) error {
	doc := &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:   uuid.NewString(),
			Date: timestamppb.Now(),
			Tools: []*sbom.Tool{
				{
					Name:    appname,
					Version: version.GetVersionInfo().GitVersion,
					Vendor:  "Carabiner Systems, Inc",
				},
			},
		},
		NodeList: nl,
	}
	for _, opt := range opts {
		opt(doc)
	}
	commentContext(doc, format)

	w := writer.New(writer.WithFormat(format))
	return w.WriteStream(doc, wr)
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	intoto "github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	gintoto "github.com/in-toto/attestation/go/v1"

	"github.com/google/uuid"
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

// nodeLlistToAttestation writes the nodelist to an attestation
func nodeListToAttestation(wr io.WriteCloser, format formats.Format, nl *sbom.NodeList) error {
	predicateType := ""
	switch format.Type() {
	case "spdx":
		predicateType = "https://spdx.dev/Document"
	case "cyclonedx":
		predicateType = "https://cyclonedx.org/bom"
	default:
		return fmt.Errorf("unsupported format to attest")
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

		if n.GetExternalReferences() != nil {
			for _, ref := range n.GetExternalReferences() {
				if ref.Type == sbom.ExternalReference_VCS {
					for algo, h := range ref.Hashes {
						sub.Digest[strings.ToLower(sbom.HashAlgorithm_name[algo])] = h
					}
				}
			}
		}

		sub.DownloadLocation = n.UrlDownload
		sub.Name = string(n.Purl())
		att.Subject = append(att.Subject, &sub)
	}

	// TODO(puerco): Drop the bcloser for a plain buffer once
	// https://github.com/protobom/protobom/pull/330 merges
	bc := bcloser{
		Buffer: bytes.Buffer{},
	}

	if err := nodeListToSbom(&bc, format, nl); err != nil {
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

func nodeListToSbom(wr io.WriteCloser, format formats.Format, nl *sbom.NodeList) error {
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

	w := writer.New(writer.WithFormat(format))
	return w.WriteStream(doc, wr)
}

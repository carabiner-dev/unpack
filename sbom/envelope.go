// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/collector/envelope"
	predicatejson "github.com/carabiner-dev/collector/predicate/json"
	"github.com/protobom/protobom/pkg/reader"
	protosbom "github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
)

var (
	// errNotEnveloped reports that the data is not an attestation at all,
	// and the caller should stand by whatever protobom said about it.
	errNotEnveloped = errors.New("data is not wrapped in a security envelope")

	// errNoEnvelopedSBOM reports that the data is an attestation, but none
	// of the predicates it carries reads as a bill of materials.
	errNoEnvelopedSBOM = errors.New("security envelope carries no SBOM predicate")
)

// parseEnveloped reads a bill of materials that travels as the predicate of
// an attestation instead of as a bare document. SBOMs are commonly shipped
// wrapped in a security envelope -- a sigstore bundle or a DSSE envelope --
// which protobom does not sniff as an SBOM format: the collector opens the
// envelope and the predicate inside goes back through protobom.
//
// Opening an envelope is not verifying it. Signatures and verification
// material travel along with the statement but nothing here checks them, so
// the dependency data this yields is exactly as trustworthy as the file it
// was read from.
func parseEnveloped(r io.ReadSeeker) (*protosbom.Document, error) {
	// The failed format sniff consumed part of the stream.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewinding SBOM stream: %w", err)
	}

	envelopes, err := envelope.Parsers.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotEnveloped, err)
	}

	errs := []error{}
	for _, env := range envelopes {
		pred := env.GetPredicate()
		if pred == nil {
			continue
		}

		// A predicate typed as plain JSON is the collector reporting that
		// nothing declared a type: it synthesizes a statement around any
		// JSON it is handed. That is not an envelope, it is the original
		// file wearing one.
		if pred.GetType() == predicatejson.PredicateType {
			continue
		}

		// The predicate type names what the payload is meant to be, but
		// only the payload settles whether protobom can read it: SBOMs
		// travel under type strings their producers pick themselves.
		doc, err := reader.New().ParseStream(bytes.NewReader(pred.GetData()))
		if err != nil {
			errs = append(errs, fmt.Errorf("predicate %q: %w", pred.GetType(), err))
			continue
		}

		logrus.Debugf("read SBOM from the %q predicate of a security envelope", pred.GetType())
		return doc, nil
	}

	if len(errs) == 0 {
		return nil, errNotEnveloped
	}
	return nil, fmt.Errorf("%w: %w", errNoEnvelopedSBOM, errors.Join(errs...))
}

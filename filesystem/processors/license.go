// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"fmt"
	"io/fs"
	"sync"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/unpack/filesystem/options"
	"github.com/carabiner-dev/unpack/license"
)

// The classifier is shared by all scanner instances: building it
// indexes the embedded license corpus once, and matching is safe for
// concurrent use.
var (
	licenseClassifier     *classifier.Classifier
	licenseClassifierOnce sync.Once
	errLicenseClassifier  error
)

func getLicenseClassifier() (*classifier.Classifier, error) {
	licenseClassifierOnce.Do(func() {
		licenseClassifier, errLicenseClassifier = assets.DefaultClassifier()
	})
	if errLicenseClassifier != nil {
		return nil, fmt.Errorf("building license classifier: %w", errLicenseClassifier)
	}
	return licenseClassifier, nil
}

func NewLicenseScanner() *LicenseScanner {
	return &LicenseScanner{}
}

// LicenseScanner is a file processor that matches file contents
// against the license classifier corpus. When a file holds a license,
// its normalized SPDX identifier is recorded as the node's license
// and concluded license; files without one are left untouched.
type LicenseScanner struct{}

func (p *LicenseScanner) Process(_ *options.Options, source fs.FS, node *sbom.Node) error {
	c, err := getLicenseClassifier()
	if err != nil {
		return err
	}

	// Open the file
	f, err := source.Open(node.GetFileName())
	if err != nil {
		return fmt.Errorf("opening %q: %w", node.GetFileName(), err)
	}
	defer f.Close() //nolint:errcheck

	results, err := c.MatchFrom(f)
	if err != nil {
		return fmt.Errorf("classifying %q: %w", node.GetFileName(), err)
	}

	// The classifier also reports header and copyright notice
	// matches; only full license matches count, and of those the one
	// matched with the highest confidence wins.
	name := ""
	confidence := 0.0
	for _, match := range results.Matches {
		if match.MatchType != "License" {
			continue
		}
		if match.Confidence > confidence {
			confidence = match.Confidence
			name = match.Name
		}
	}
	if name == "" {
		return nil
	}

	id := license.Normalize(name, "")
	node.Licenses = []string{id}
	node.LicenseConcluded = id
	return nil
}

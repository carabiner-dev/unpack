// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// This program downloads the latest SPDX license list and CycloneDX
// license mapping from GitHub and writes them locally for embedding.
//
// Run via: go generate ./license/
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	spdxURL    = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
	mappingURL = "https://raw.githubusercontent.com/CycloneDX/cyclonedx-core-java/master/src/main/resources/license-mapping.json"
)

type fullLicense struct {
	LicenseID             string   `json:"licenseId"`
	Name                  string   `json:"name"`
	SeeAlso               []string `json:"seeAlso"`
	IsDeprecatedLicenseID bool     `json:"isDeprecatedLicenseId"`
}

type fullList struct {
	LicenseListVersion string        `json:"licenseListVersion"`
	Licenses           []fullLicense `json:"licenses"`
}

type slimLicense struct {
	LicenseID string   `json:"licenseId"`
	Name      string   `json:"name"`
	SeeAlso   []string `json:"seeAlso"`
}

type slimList struct {
	LicenseListVersion string        `json:"licenseListVersion"`
	Licenses           []slimLicense `json:"licenses"`
}

func main() {
	if err := updateSPDXLicenses(); err != nil {
		fmt.Fprintf(os.Stderr, "SPDX licenses: %v\n", err)
		os.Exit(1)
	}

	if err := updateCDXMapping(); err != nil {
		fmt.Fprintf(os.Stderr, "CycloneDX mapping: %v\n", err)
		os.Exit(1)
	}
}

func updateSPDXLicenses() error {
	fmt.Println("Fetching SPDX license list from", spdxURL)

	data, err := fetch(spdxURL)
	if err != nil {
		return err
	}

	var full fullList
	if err := json.Unmarshal(data, &full); err != nil {
		return fmt.Errorf("parsing: %w", err)
	}

	// Strip to essential fields and skip deprecated licenses
	slim := slimList{LicenseListVersion: full.LicenseListVersion}
	for _, l := range full.Licenses {
		if l.IsDeprecatedLicenseID {
			continue
		}
		slim.Licenses = append(slim.Licenses, slimLicense{
			LicenseID: l.LicenseID,
			Name:      l.Name,
			SeeAlso:   l.SeeAlso,
		})
	}

	out, err := json.Marshal(slim)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}

	if err := os.WriteFile("licenses.json", out, 0o644); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	fmt.Printf("Wrote licenses.json: %d licenses (version %s, %d bytes)\n",
		len(slim.Licenses), slim.LicenseListVersion, len(out))
	return nil
}

func updateCDXMapping() error {
	fmt.Println("Fetching CycloneDX license mapping from", mappingURL)

	data, err := fetch(mappingURL)
	if err != nil {
		return err
	}

	// Validate it's valid JSON
	var mapping []json.RawMessage
	if err := json.Unmarshal(data, &mapping); err != nil {
		return fmt.Errorf("parsing: %w", err)
	}

	// Re-marshal compact
	out, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}

	if err := os.WriteFile("mapping.json", out, 0o644); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	fmt.Printf("Wrote mapping.json: %d entries (%d bytes)\n", len(mapping), len(out))
	return nil
}

func fetch(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	return data, nil
}

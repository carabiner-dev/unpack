// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ComposerJSON is the manifest, read for what the lock does not carry: the
// project's own identity and which requirements are direct.
type ComposerJSON struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Homepage    string            `json:"homepage"`
	Require     map[string]string `json:"require"`
	RequireDev  map[string]string `json:"require-dev"`

	// RawLicense is a string or a list; Licenses() reads both.
	RawLicense json.RawMessage `json:"license"`
}

// ParseComposerJSON reads a composer.json document.
func ParseComposerJSON(data []byte) (*ComposerJSON, error) {
	manifest := &ComposerJSON{}
	if err := json.Unmarshal(data, manifest); err != nil {
		return nil, fmt.Errorf("parsing composer.json: %w", err)
	}
	return manifest, nil
}

// ReadComposerJSON reads a composer.json from a directory.
func ReadComposerJSON(workDir string) (*ComposerJSON, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "composer.json"))
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	return ParseComposerJSON(data)
}

// Licenses returns the manifest's license declaration, which the schema
// allows as one identifier or a list of them.
func (m *ComposerJSON) Licenses() []string {
	if len(m.RawLicense) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(m.RawLicense, &one) == nil && one != "" {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(m.RawLicense, &many) == nil {
		return many
	}
	return nil
}

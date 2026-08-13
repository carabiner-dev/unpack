// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCodebaseOutputFilename pins the names written when --multi sends each
// codebase to its own file. Callers collecting the results glob for these,
// so the extension is part of the contract.
func TestCodebaseOutputFilename(t *testing.T) {
	t.Parallel()

	t.Run("extension per format", func(t *testing.T) {
		t.Parallel()
		for name, expected := range map[string]string{
			formatSPDX:  "golang.spdx.json",
			formatSPDX3: "golang.spdx3.json",
			formatCDX:   "golang.cdx.json",
			formatCDXS:  "golang.cdx.json",
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				opts := &extractOptions{formatOptions: formatOptions{Format: name}}
				require.Equal(t, expected, codebaseOutputFilename(opts, "golang:."))
			})
		}
	})

	t.Run("id sanitization", func(t *testing.T) {
		t.Parallel()
		opts := &extractOptions{
			formatOptions: formatOptions{Format: formatSPDX3},
			OutputPrefix:  "org-repo-",
		}
		for id, expected := range map[string]string{
			"golang:.":           "org-repo-golang.spdx3.json",
			"golang:source/api":  "org-repo-golang-source-api.spdx3.json",
			"npm:frontend/admin": "org-repo-npm-frontend-admin.spdx3.json",
		} {
			require.Equal(t, expected, codebaseOutputFilename(opts, id), "id %q", id)
		}
	})

	// Every writable format needs a name that identifies it. Falling through
	// to the bare ".json" default leaves the document unidentifiable on disk
	// and breaks every caller globbing for a known extension, which is how
	// SPDX 3 slipped through when it was added.
	t.Run("no sbom format falls through to the default", func(t *testing.T) {
		t.Parallel()
		seen := map[string]string{}
		for _, name := range sbomFormats {
			got := codebaseOutputFilename(&extractOptions{
				formatOptions: formatOptions{Format: name},
			}, "golang:.")
			ext := strings.TrimPrefix(got, "golang")
			require.NotEqual(t, ".json", ext, "%s has no extension of its own", name)
			require.True(t, strings.HasSuffix(ext, ".json"), "%s should still write JSON, got %q", name, ext)
			seen[name] = ext
		}
		// The two CycloneDX spellings are one format, so they share; SPDX 2.3
		// and SPDX 3 must not.
		require.NotEqual(t, seen[formatSPDX], seen[formatSPDX3],
			"SPDX 2.3 and SPDX 3 must be distinguishable on disk")
	})
}

// TestExtractOptionsPlatform pins the shape the --platform flag accepts:
// os or os/arch. Which values mean anything is the business of the
// ecosystems that read the platform, so the CLI checks only the shape.
func TestExtractOptionsPlatform(t *testing.T) {
	t.Parallel()

	for platform, valid := range map[string]bool{
		"":              true,
		"linux":         true,
		"linux/arm64":   true,
		"windows/amd64": true,
		"/":             false,
		"linux/":        false,
		"/arm64":        false,
		"linux/a/b":     false,
	} {
		t.Run("platform "+platform, func(t *testing.T) {
			t.Parallel()
			opts := &extractOptions{
				formatOptions: formatOptions{Format: formatTree},
				Path:          ".",
				Networking:    "essential",
				Platform:      platform,
			}
			err := opts.Validate()
			if valid {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "invalid platform")
		})
	}
}

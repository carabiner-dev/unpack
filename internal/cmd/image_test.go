// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatOptionsValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		opts    formatOptions
		wantErr string
	}{
		{"default tree", formatOptions{Format: formatTree}, ""},
		{"spdx", formatOptions{Format: formatSPDX}, ""},
		{"spdx3", formatOptions{Format: formatSPDX3}, ""},
		{"bogus format", formatOptions{Format: "yaml"}, "invalid format"},
		{"attest needs sbom format", formatOptions{Format: formatTree, Attest: true}, "attestations can only"},
		{"attest with cdx", formatOptions{Format: formatCDXS, Attest: true}, ""},
		{"attest with spdx3", formatOptions{Format: formatSPDX3, Attest: true}, ""},
		{"sign implies attest", formatOptions{Format: formatSPDX, Sign: true}, ""},
		{"sign with tree fails", formatOptions{Format: formatTree, Sign: true}, "attestations can only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.opts.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestFormatOptionsSignImpliesAttest(t *testing.T) {
	t.Parallel()
	opts := formatOptions{Format: formatSPDX, Sign: true}
	require.NoError(t, opts.Validate())
	assert.True(t, opts.Attest)
}

func TestFormatOptionsDefaultToSPDX(t *testing.T) {
	t.Parallel()
	opts := &formatOptions{}
	cmd := &cobra.Command{}
	opts.AddFlags(cmd)

	require.NoError(t, cmd.PersistentFlags().Set("attest", "true"))
	opts.DefaultToSPDX(cmd)
	assert.Equal(t, formatSPDX, opts.Format)

	// An explicit format is respected.
	opts2 := &formatOptions{}
	cmd2 := &cobra.Command{}
	opts2.AddFlags(cmd2)
	require.NoError(t, cmd2.PersistentFlags().Set("format", formatCDXS))
	require.NoError(t, cmd2.PersistentFlags().Set("attest", "true"))
	opts2.DefaultToSPDX(cmd2)
	assert.Equal(t, formatCDXS, opts2.Format)
}

// imageTestDB is a one-package apk database for the CLI round-trip.
const imageTestDB = `P:musl
V:1.2.6-r2
A:x86_64
T:the musl c library (libc) implementation
L:MIT
o:musl
F:lib
R:ld-musl-x86_64.so.1
Z:Q1HDbpApgJLhKPJN6IjaA7wJ3Oa4o=
`

// pushCmdTestImage pushes a minimal apk-carrying image to an in-memory
// registry and returns its reference.
func pushCmdTestImage(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	host, err := url.Parse(srv.URL)
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range []struct{ name, content string }{
		{"lib/apk/db/installed", imageTestDB},
		{"etc/os-release", "ID=alpine\nVERSION_ID=3.24.0\n"},
	} {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.content)),
		}))
		_, err := tw.Write([]byte(e.content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	img, err = mutate.ConfigFile(img, &v1.ConfigFile{Architecture: "amd64", OS: "linux"})
	require.NoError(t, err)

	refStr := host.Host + "/test/minialpine:v1"
	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img))
	return refStr
}

// TestImageCommandSPDX runs the image subcommand end to end: pull from a
// local registry, extract, and write an SPDX SBOM to a file.
func TestImageCommandSPDX(t *testing.T) {
	commandLineOpts.logLevel = "info"
	refStr := pushCmdTestImage(t)
	outPath := filepath.Join(t.TempDir(), "image.spdx.json")

	root := &cobra.Command{Use: "test"}
	addImage(root)
	root.SetArgs([]string{"image", "--format", "spdx", "--output", outPath, refStr})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "SPDX-2.3", doc["spdxVersion"])

	out := string(data)
	assert.Contains(t, out, refStr, "the image node carries the reference")
	assert.Contains(t, out, "pkg:oci/minialpine@sha256%3A")
	assert.Contains(t, out, "pkg:apk/alpine/musl@1.2.6-r2")
}

// TestImageCommandFiles verifies --files flows through to the system
// decomposers.
func TestImageCommandFiles(t *testing.T) {
	commandLineOpts.logLevel = "info"
	refStr := pushCmdTestImage(t)
	outPath := filepath.Join(t.TempDir(), "image.spdx.json")

	root := &cobra.Command{Use: "test"}
	addImage(root)
	root.SetArgs([]string{"image", "--files", "-f", "spdx", "-o", outPath, refStr})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "/lib/ld-musl-x86_64.so.1",
		"the package file list should be in the SBOM")
}

func TestImageCommandNeedsReference(t *testing.T) {
	commandLineOpts.logLevel = "info"
	root := &cobra.Command{Use: "test"}
	addImage(root)
	root.SetArgs([]string{"image"})
	root.SetErr(io.Discard)
	root.SetOut(io.Discard)
	require.Error(t, root.Execute())
}

func TestImageCommandRejectsBadFormat(t *testing.T) {
	commandLineOpts.logLevel = "info"
	root := &cobra.Command{Use: "test"}
	addImage(root)
	root.SetArgs([]string{"image", "-f", "yaml", "example.com/img:v1"})
	root.SetErr(io.Discard)
	root.SetOut(io.Discard)
	require.ErrorContains(t, root.Execute(), "invalid format")
}

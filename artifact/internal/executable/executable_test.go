// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package executable

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/unpack/artifact/internal/exetest"
)

func TestMagic(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		header []byte
		want   bool
	}{
		"elf":        {[]byte("\x7fELF\x02\x01\x01"), true},
		"pe":         {[]byte("MZ\x90\x00\x03"), true},
		"macho64 le": {[]byte("\xcf\xfa\xed\xfe\x07"), true},
		"macho32 be": {[]byte("\xfe\xed\xfa\xce\x00"), true},
		"fat macho":  {[]byte("\xca\xfe\xba\xbe"), false},
		"script":     {[]byte("#!/bin/sh\n"), false},
		"short":      {[]byte("\x7fE"), false},
		"empty":      {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, Magic(tc.header))
		})
	}
}

func TestSection(t *testing.T) {
	t.Parallel()
	payload := []byte("hello from a section")
	for name, build := range map[string]func(string, []byte) []byte{
		"elf": exetest.ELF, "pe": exetest.PE, "macho": exetest.MachO,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			exe := build(".dep-v0", payload)

			got, err := Section(bytes.NewReader(exe), ".dep-v0")
			require.NoError(t, err)
			assert.Equal(t, payload, got)

			got, err = Section(bytes.NewReader(exe), ".other")
			require.NoError(t, err)
			assert.Nil(t, got, "a missing section is nil, not an error")

			// A section header pointing past the end of the file is
			// disowned, not reported.
			got, err = Section(bytes.NewReader(exe[:len(exe)-len(payload)]), ".dep-v0")
			require.NoError(t, err)
			assert.Nil(t, got)
		})
	}

	t.Run("not executables", func(t *testing.T) {
		t.Parallel()
		for _, data := range [][]byte{nil, []byte("MZ"), []byte("\x7fELF garbage"), []byte("plain text file")} {
			got, err := Section(bytes.NewReader(data), ".dep-v0")
			require.NoError(t, err)
			assert.Nil(t, got)
		}
	})
}

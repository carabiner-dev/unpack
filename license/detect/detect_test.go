// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

const mit = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

func TestText(t *testing.T) {
	t.Parallel()
	require.Equal(t, "MIT", Text([]byte(mit)))
	require.Empty(t, Text([]byte("All rights reserved. Ask before using.")))
	require.Empty(t, Text(nil))

	// This repository's own license.
	apache, err := os.ReadFile("../../LICENSE.txt")
	require.NoError(t, err)
	require.Equal(t, "Apache-2.0", Text(apache))
}

func TestIsFileName(t *testing.T) {
	t.Parallel()
	for name, expected := range map[string]bool{
		"LICENSE": true, "license.txt": true, "Licence.md": true, "COPYING": true,
		"LICENSE-MIT": false, "README.md": false, "": false,
	} {
		require.Equal(t, expected, IsFileName(name), name)
	}
}

func TestDir(t *testing.T) {
	t.Parallel()
	file := func(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }

	for name, tc := range map[string]struct {
		fsys         fstest.MapFS
		id, fileName string
	}{
		"a license file":    {fstest.MapFS{"LICENSE": file(mit), "README.md": file("hello")}, "MIT", "LICENSE"},
		"whatever its case": {fstest.MapFS{"license.txt": file(mit)}, "MIT", "license.txt"},
		// A file that is no license is passed over for the next name.
		"an unrecognized file, then a license": {
			fstest.MapFS{"LICENSE": file("see COPYING"), "COPYING": file(mit)}, "MIT", "COPYING",
		},
		"only an unrecognized file": {fstest.MapFS{"LICENSE": file("ask first")}, "", ""},
		// Only the top of the directory is looked at.
		"a license deeper down":   {fstest.MapFS{"vendor/lib/LICENSE": file(mit)}, "", ""},
		"a directory by the name": {fstest.MapFS{"LICENSE/README": file(mit)}, "", ""},
		"nothing":                 {fstest.MapFS{}, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id, fileName := Dir(tc.fsys)
			require.Equal(t, tc.id, id)
			require.Equal(t, tc.fileName, fileName)
		})
	}
}

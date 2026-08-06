// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"os"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestLicenseScannerProcess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		path    string
		expect  []string
		mustErr bool
	}{
		{"license", "MIT.txt", []string{"MIT"}, false},
		{"no-license", "notes.txt", nil, false},
		{"notfound", "not-existing.txt", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			node := sbom.NewNode()
			node.Type = sbom.Node_FILE
			node.Name = tc.path
			node.FileName = tc.path

			err := NewLicenseScanner().Process(nil, os.DirFS("testdata"), node)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if len(tc.expect) > 0 {
				require.Equal(t, tc.expect, node.GetLicenses())
				require.Equal(t, tc.expect[0], node.GetLicenseConcluded())
			} else {
				require.Empty(t, node.GetLicenses())
				require.Empty(t, node.GetLicenseConcluded())
			}
		})
	}
}

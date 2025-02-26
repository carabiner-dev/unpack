package rust

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/unpack/api/v1"
)

func TestParseCargoOutput(t *testing.T) {
	for _, tc := range []struct {
		name          string
		input         string
		expectedLen   int
		expectedRoots int
		mustErr       bool
	}{
		{
			name:          "simple",
			input:         "0skootrs-bin v0.1.0 (/home/puerco/projects/skootrs/skootrs-bin)\n1base64 v0.22.0\n1clap v4.5.4\n2clap_builder v4.5.2\n3anstream v0.6.13\n",
			expectedLen:   5,
			expectedRoots: 1,
			mustErr:       false,
		},
		{
			name:          "duplicate-dependency",
			input:         "0skootrs-bin v0.1.0 (/home/puerco/projects/skootrs/skootrs-bin)\n1base64 v0.22.0\n1clap v4.5.4\n2clap_builder v4.5.2\n3anstream v0.6.13\n2anstream v0.6.13\n",
			expectedLen:   5,
			expectedRoots: 1,
			mustErr:       false,
		},
		{
			name:    "bad-input",
			input:   "skootrs-bin v0.1.0 (/home/puerco/projects/skootrs/skootrs-bin)\n1base64 v0.22.0\n1clap v4.5.4\n2clap_builder v4.5.2\n3anstream v0.6.13\n2anstream v0.6.13\n",
			mustErr: true,
		},
		{
			name:          "two-roots",
			input:         "0skootrs-bin v0.1.0 (/home/puerco/projects/skootrs/skootrs-bin)\n1base64 v0.22.0\n1clap v4.5.4\n0clap_builder v4.5.2\n",
			expectedLen:   4,
			expectedRoots: 2,
			mustErr:       false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			nl := sbom.NewNodeList()

			d := New()
			opts := api.Options{}
			opts.SetDecomposerOptions(d, Options{
				GenerateNormalDependencies: true,
			})

			err := d.parseCargoOutput(nl, tc.input, sbom.Edge_dependsOn, map[string]*sbom.Node{})
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, nl.Nodes, tc.expectedLen)
			require.Len(t, nl.RootElements, tc.expectedRoots)
		})
	}
}

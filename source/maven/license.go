// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import "github.com/carabiner-dev/unpack/license"

// NormalizeLicense maps a Maven POM license to its SPDX identifier
// using the shared license normalization package.
func NormalizeLicense(lic License) string {
	return license.Normalize(lic.Name, lic.URL)
}

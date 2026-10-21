// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dependencies

import (
	"testing"
)

// The id is the platform's canonical one: the same codebase gets the same
// id however the path was spelled.
func TestCodebaseIDIsCanonical(t *testing.T) {
	for _, in := range []string{"./backend", "backend", "backend/", "./backend/."} {
		id, err := GenerateCodebaseID("golang", in)
		if err != nil {
			t.Fatalf("GenerateCodebaseID(golang, %q): %v", in, err)
		}
		if id != "golang:backend" {
			t.Errorf("GenerateCodebaseID(golang, %q) = %q, want golang:backend", in, id)
		}
	}
	if id, err := GenerateCodebaseID("npm", "."); err != nil || id != "npm:." {
		t.Errorf("root id = %q, %v; want npm:.", id, err)
	}
	for _, bad := range []struct{ lang, path string }{{"Go", "x"}, {"golang", ""}, {"golang", "/abs"}, {"golang", "../out"}} {
		if _, err := GenerateCodebaseID(bad.lang, bad.path); err == nil {
			t.Errorf("GenerateCodebaseID(%q, %q) must fail", bad.lang, bad.path)
		}
	}
}

func TestParseCodebaseIDAcceptsOldAndCanonicalForms(t *testing.T) {
	for _, in := range []string{"golang:./services/api", "golang:services/api", "golang:services/api/"} {
		lang, p, err := ParseCodebaseID(in)
		if err != nil {
			t.Fatalf("ParseCodebaseID(%q): %v", in, err)
		}
		if lang != "golang" || p != "services/api" {
			t.Errorf("ParseCodebaseID(%q) = %q, %q; want golang, services/api", in, lang, p)
		}
	}
	for _, bad := range []string{"", "golang", ":x", "golang:", "golang:/x"} {
		if _, _, err := ParseCodebaseID(bad); err == nil {
			t.Errorf("ParseCodebaseID(%q) must fail", bad)
		}
	}
}

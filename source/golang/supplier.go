// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

// This file names who a Go module is supplied by.
//
// A module declares nobody: go.mod has no author, and there is no registry
// account behind a version, which is published by tagging a repository.
// What a module does state is its path, and the path says who controls
// the name: to publish under github.com/spf13 one has to hold that
// account, and to serve golang.org/x one has to hold that domain. That
// control is what Go itself trusts a module by, so it is what stands for
// the supplier here: the owner of the repository on a code host, the
// domain otherwise.
//
// It is an identifier and not the name an entity goes by, and nothing says
// whether a person or an organization is behind it. The supplier carries
// its address, so that where the name was taken from can be seen.

// codeHosts are the hosts whose paths open with the owner of a repository,
// as host/owner/repository.
var codeHosts = map[string]struct{}{
	"github.com":    {},
	"gitlab.com":    {},
	"bitbucket.org": {},
	"codeberg.org":  {},
	"gitea.com":     {},
	"gitee.com":     {},
	"git.sr.ht":     {},
}

const (
	// gopkgHost is a redirector onto GitHub, by a fixed rule: gopkg.in/pkg.v3
	// is github.com/go-pkg/pkg and gopkg.in/user/pkg.v3 is
	// github.com/user/pkg. The host itself supplies nothing.
	gopkgHost = "gopkg.in"

	githubHost = "github.com"
)

// stdlibSupplier is who the Go distribution names as the standard
// library's authors.
func stdlibSupplier() *sbom.Person {
	return &sbom.Person{Name: "The Go Authors", Url: "https://go.dev", IsOrg: true}
}

// moduleSupplier names the supplier of the module at a path, or nil when
// the path names nobody: one that is no module path, or stops short of an
// owner on a host where the owner is who it would be.
func moduleSupplier(modPath string) *sbom.Person {
	parts := strings.Split(modPath, "/")
	host := parts[0]
	// A module path opens with a host, and a host has a dot.
	if !strings.Contains(host, ".") {
		return nil
	}

	switch {
	case host == gopkgHost:
		if len(parts) < 2 || parts[1] == "" {
			return nil
		}
		owner := parts[1]
		if len(parts) == 2 {
			// gopkg.in/pkg.v3: the package without its version, under
			// the owner the redirector derives from it.
			name, _, _ := strings.Cut(parts[1], ".")
			if name == "" {
				return nil
			}
			owner = "go-" + name
		}
		return ownerOn(githubHost, owner)

	case isCodeHost(host):
		if len(parts) < 2 || parts[1] == "" {
			return nil
		}
		return ownerOn(host, parts[1])

	default:
		return &sbom.Person{Name: host, Url: "https://" + host, IsOrg: true}
	}
}

func isCodeHost(host string) bool {
	_, ok := codeHosts[strings.ToLower(host)]
	return ok
}

// ownerOn names the owner of a repository on a code host.
func ownerOn(host, owner string) *sbom.Person {
	return &sbom.Person{Name: owner, Url: "https://" + host + "/" + owner, IsOrg: true}
}

// moduleSuppliers is moduleSupplier as the list a node takes.
func moduleSuppliers(modPath string) []*sbom.Person {
	if supplier := moduleSupplier(modPath); supplier != nil {
		return []*sbom.Person{supplier}
	}
	return nil
}

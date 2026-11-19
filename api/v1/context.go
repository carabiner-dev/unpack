// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import "github.com/protobom/protobom/pkg/sbom"

// GenerationContext is the point of a software's life at which the data of
// an SBOM was read, and so what there was to read: a source tree before
// any build, the build itself, or something already built. The values are
// the SBOM types CISA defines, as protobom names them, so a document can
// state them as they are.
type GenerationContext = sbom.DocumentType_SBOMType

const (
	// ContextSource is data read from a source tree and the manifests and
	// lock files in it, before anything is built.
	ContextSource = sbom.DocumentType_SOURCE

	// ContextBuild is data recorded by the build, or by the tool that
	// runs it, while it resolved what to build with.
	ContextBuild = sbom.DocumentType_BUILD

	// ContextAnalyzed is data read by taking apart something already
	// built: a binary, an image, the packages installed in one.
	ContextAnalyzed = sbom.DocumentType_ANALYZED
)

// ContextReporter is implemented by decomposers that know in which context
// the data they return was read. It is the decomposer's to say: the same
// command can run decomposers that read source and others that read what
// was built from it.
type ContextReporter interface {
	// GenerationContext returns the context the decomposer reads in.
	GenerationContext() GenerationContext
}

// GenerationContextOf returns the context a decomposer reads in, and false
// when it does not say.
func GenerationContextOf(d Decomposer) (GenerationContext, bool) {
	reporter, ok := d.(ContextReporter)
	if !ok {
		return sbom.DocumentType_OTHER, false
	}
	return reporter.GenerationContext(), true
}

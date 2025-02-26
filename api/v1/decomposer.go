package v1

import "github.com/protobom/protobom/pkg/sbom"

// Decomposer is an interface that abstracts the logic of dependency extraction
// from a codebase.
type Decomposer interface {
	Extract(*DecomposerOptions) (*sbom.NodeList, error)
	Requirements(*DecomposerOptions) []Requirement
	DefaultOptions() any
}

// SourceDecomposer is a decomposer that reads data from a codebase.
type SourceDecomposer interface {
}

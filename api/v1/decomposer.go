package v1

import "github.com/protobom/protobom/pkg/sbom"

// Decomposer is an interface that abstracts the logic of dependency extraction
// from a codebase.
type Decomposer interface {
	Extract(*Options) (*sbom.NodeList, error)
	Requirements() []Requirement
	DefaultOptions() any
}

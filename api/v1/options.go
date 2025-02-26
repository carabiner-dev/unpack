package v1

import "fmt"

// DecomposerOptions is the options set that goes into an Extract() run in
// a decomposer. They are meant to be ephimeral, for the invocation only, and
// derived from the Unpacker configuration whe invoked from there.
type DecomposerOptions struct {
	WorkDir           string
	decomposerOptions map[string]any
}

func (so *DecomposerOptions) SetDecomposerOptions(dec Decomposer, opts any) {
	if dec == nil {
		return
	}
	if so.decomposerOptions == nil {
		so.decomposerOptions = map[string]any{}
	}
	so.decomposerOptions[fmt.Sprintf("%T", dec)] = opts
}

func (so *DecomposerOptions) GetDecomposerOptions(dec Decomposer) any {
	if so.decomposerOptions == nil {
		return nil
	}
	if opts, ok := so.decomposerOptions[fmt.Sprintf("%T", dec)]; ok {
		return opts
	}
	return nil
}

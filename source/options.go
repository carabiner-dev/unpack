package source

import "fmt"

type Options struct {
	WorkDir           string
	decomposerOptions map[string]any
}

func (so *Options) SetDecomposerOptions(dec Decomposer, opts any) {
	if dec == nil {
		return
	}
	if so.decomposerOptions == nil {
		so.decomposerOptions = map[string]any{}
	}
	so.decomposerOptions[fmt.Sprintf("%T", dec)] = opts
}

func (so *Options) GetDecomposerOptions(dec Decomposer) any {
	if so.decomposerOptions == nil {
		return nil
	}
	if opts, ok := so.decomposerOptions[fmt.Sprintf("%T", dec)]; ok {
		return opts
	}
	return nil
}

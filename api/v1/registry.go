// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import "fmt"

// UnpackerBuilder returns a new, ready-to-use Unpacker instance.
type UnpackerBuilder func() Unpacker

// unpackerRegistry maps a subject type (as returned by
// DecomposableSubject.DecomposableType) to the builder that produces the
// unpacker capable of processing it. Concrete unpacker packages register
// themselves here from their init() functions.
var unpackerRegistry = map[string]UnpackerBuilder{}

// RegisterUnpacker registers an unpacker builder for a subject type. Calling it
// more than once for the same subject type replaces the previous builder.
func RegisterUnpacker(subjectType string, builder UnpackerBuilder) {
	unpackerRegistry[subjectType] = builder
}

// UnpackerFor returns a new unpacker capable of processing the given subject,
// or an error if no unpacker is registered for the subject's type. This is the
// routing mechanism unpackers use to dispatch child subjects they discover.
func UnpackerFor(subject DecomposableSubject) (Unpacker, error) {
	if subject == nil {
		return nil, fmt.Errorf("cannot route a nil subject to an unpacker")
	}
	builder, ok := unpackerRegistry[subject.DecomposableType()]
	if !ok {
		return nil, fmt.Errorf("no unpacker registered for subject type %q", subject.DecomposableType())
	}
	return builder(), nil
}

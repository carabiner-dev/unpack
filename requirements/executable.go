// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package requirements

import (
	"fmt"
	"os/exec"

	api "github.com/carabiner-dev/unpack/api/v1"
)

var _ api.Requirement = (*Executable)(nil)

type Executable struct {
	Command string
}

func (er *Executable) Description() string {
	if er.Command == "" {
		return "This executable requirement is empty (mis configured?())"
	}
	return fmt.Sprintf(
		"Requires the %q executable to be available in the path", er.Command,
	)
}

// Check verifies the binaries can be run
func (er *Executable) Check() bool {
	if er.Command == "" {
		return true
	}
	_, err := exec.LookPath(er.Command)
	if err != nil {
		return false
	}

	return true
}

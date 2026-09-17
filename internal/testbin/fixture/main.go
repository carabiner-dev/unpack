// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Command fixture is a tiny Go program the tests build to get an executable
// with module dependencies in its build information. It imports one module
// from this repository's own go.mod so the build never needs the network.
package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	fmt.Println(uuid.NewString())
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

/*
Package requirements collects a few implementations of the v1.Requirement
interface. This is a simple strcut that helps decomposers express and check
what they need to extract dependency data.

## Interface and Methods

The interface is really simple:

```golang

	type Requirement interface {
		Description() string
		Check() bool
	}

```

Any implementation needs to expose two methods:

### Description()

# This function returns human readable text to expose to users in CLIs, etc

### Check()

Check returns a boolean that indicates if the requirement is met.

## Available Implementations

- [Network] is a requirements implementation that checks for network connectivity
to a specific host.

- [Executable] looks for an executable in the system.
*/
package requirements

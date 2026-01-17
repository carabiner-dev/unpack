// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package requirements

import (
	"context"
	"fmt"
	"net"

	api "github.com/carabiner-dev/unpack/api/v1"
)

// Network is a requirements implementation that checks that the runtime
// is able to connect to a specific host and port.
type Network struct {
	Host  string
	Port  int
	Proto string
}

var _ api.Requirement = (*Network)(nil)

func (nr *Network) Description() string {
	if nr.Host == "" || nr.Port == 0 || nr.Proto == "" {
		return "This network requirement is empty (probably misconfigured?)"
	}
	return fmt.Sprintf(
		"Requires opening network connections to %s://%s:%d",
		nr.Proto, nr.Host, nr.Port,
	)
}

// Check verifies the binaries can be run
func (nr *Network) Check(ctx context.Context) bool {
	if nr.Proto == "" || nr.Port == 0 || nr.Host == "" {
		return true
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, nr.Proto, net.JoinHostPort(nr.Host, fmt.Sprintf("%d", nr.Port)))
	if err != nil {
		return false
	}
	_ = conn.Close() //nolint:errcheck

	return true
}

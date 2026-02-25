//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

const dscpEF = 46

func applyUDPSocketQoS(conn *net.UDPConn, enabled bool) error {
	if conn == nil {
		return fmt.Errorf("udp socket is nil")
	}

	tos := 0
	if enabled {
		// DSCP EF(46) with ECN bits cleared.
		tos = dscpEF << 2
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to access socket descriptor: %w", err)
	}

	var ipErr error
	var ipv6Err error
	controlErr := rawConn.Control(func(fd uintptr) {
		ipErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		ipv6Err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
	})
	if controlErr != nil {
		return fmt.Errorf("failed to apply socket options: %w", controlErr)
	}

	if ipErr != nil && ipv6Err != nil {
		return fmt.Errorf("setsockopt failed for both IPv4 and IPv6 (ip=%v, ipv6=%v)", ipErr, ipv6Err)
	}
	return nil
}

//go:build !linux

package main

import "net"

func applyUDPSocketQoS(_ *net.UDPConn, _ bool) error {
	return nil
}

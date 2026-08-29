package main

import (
	"net"
	"strings"
	"testing"
)

func TestBuildRelayUDPAddrCandidatesPrefersIPv6(t *testing.T) {
	candidates, err := buildRelayUDPAddrCandidates([]net.IPAddr{
		{IP: net.ParseIP("198.51.100.20")},
		{IP: net.ParseIP("2001:db8::20")},
	}, 50000, false)
	if err != nil {
		t.Fatalf("build candidates: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(candidates))
	}
	if candidates[0].IP.To4() != nil {
		t.Fatalf("first candidate must be IPv6, got %s", candidates[0])
	}
	if candidates[1].IP.To4() == nil {
		t.Fatalf("second candidate must be IPv4, got %s", candidates[1])
	}
}

func TestBuildRelayUDPAddrCandidatesForceIPv4(t *testing.T) {
	candidates, err := buildRelayUDPAddrCandidates([]net.IPAddr{
		{IP: net.ParseIP("2001:db8::20")},
		{IP: net.ParseIP("198.51.100.20")},
	}, 50000, true)
	if err != nil {
		t.Fatalf("build forced IPv4 candidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].IP.To4() == nil {
		t.Fatalf("forced IPv4 candidates = %#v, want only IPv4", candidates)
	}

	if _, err := buildRelayUDPAddrCandidates([]net.IPAddr{{IP: net.ParseIP("2001:db8::20")}}, 50000, true); err == nil {
		t.Fatal("forcing IPv4 for an IPv6-only relay must fail")
	}
}

func TestAdvanceRelayAddressUsesNextCandidate(t *testing.T) {
	ipv6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::20"), Port: 50000}
	ipv4 := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 50000}
	session := &relaySession{
		relayAddr:  ipv6,
		relayAddrs: []*net.UDPAddr{ipv6, ipv4},
	}

	from, to, changed := session.advanceRelayAddress()
	if !changed {
		t.Fatal("expected relay candidate to advance")
	}
	if !udpAddrEqual(from, ipv6) || !udpAddrEqual(to, ipv4) || !udpAddrEqual(session.relayAddr, ipv4) {
		t.Fatalf("unexpected relay fallback: from=%v to=%v active=%v", from, to, session.relayAddr)
	}
}

func TestRelayAddressFallbackEventOmitsEndpointDetails(t *testing.T) {
	var event serverEvent
	session := &relaySession{
		cb: sessionCallbacks{
			onEvent: func(next serverEvent) {
				event = next
			},
		},
	}
	from := &net.UDPAddr{IP: net.ParseIP("2001:db8::20"), Port: 50000}
	to := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 50000}
	session.emitRelayAddressFallback(from, to, "join send failed: network is unreachable")

	if event.Type != "status" || event.Level != "debug" || event.Message != "Relay address fallback applied" {
		t.Fatalf("unexpected relay fallback event: %#v", event)
	}
	for _, detail := range []string{from.String(), to.String(), "network is unreachable"} {
		if strings.Contains(event.Message, detail) {
			t.Fatalf("relay fallback event exposed endpoint detail %q: %#v", detail, event)
		}
	}
}

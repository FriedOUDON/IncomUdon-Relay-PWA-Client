package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestControlAuthV1Vector(t *testing.T) {
	ctx, err := newControlAuthContext("test-password", 100, 1)
	if err != nil {
		t.Fatalf("new control auth context: %v", err)
	}
	// Pin the random session state to the published deterministic vector.
	ctx.clientSessionID = 0x12345678
	ctx.nextCounter = 2

	packet := ctx.buildPacket(pktPttOn, 100, 1002, 42, nil)
	wantHeader := decodeControlAuthHex(t, "0102001c00000064000003ea002a0002123456780000000200000001")
	wantTag := decodeControlAuthHex(t, "f4df8ba41610f2a6f4a592620e51130a")
	if len(packet) != len(wantHeader)+len(wantTag) {
		t.Fatalf("packet length = %d, want %d", len(packet), len(wantHeader)+len(wantTag))
	}
	if !bytes.Equal(packet[:len(wantHeader)], wantHeader) {
		t.Fatalf("header = %x, want %x", packet[:len(wantHeader)], wantHeader)
	}
	if !bytes.Equal(packet[len(wantHeader):], wantTag) {
		t.Fatalf("tag = %x, want %x", packet[len(wantHeader):], wantTag)
	}
}

func TestControlAuthV1RejectsTamperedRelayPacket(t *testing.T) {
	ctx, err := newControlAuthContext("test-password", 100, 1)
	if err != nil {
		t.Fatalf("new control auth context: %v", err)
	}
	// Build a Relay-authenticated challenge and then prove a payload change is
	// rejected before any caller can change session state.
	prefix := buildSecurePacketPrefix(pktAuthChallenge, 100, 0, 1, uint64(0x87654321)<<32|1, 1, packetFlagControlAuthV1)
	payload := make([]byte, 20)
	valid := append(append([]byte{}, prefix...), payload...)
	valid = append(valid, ctx.tag(prefix, payload)...)
	parsed, ok := parsePacket(valid)
	if !ok || !ctx.verifyRelayPacket(parsed) {
		t.Fatal("valid relay packet was rejected")
	}
	secondPrefix := buildSecurePacketPrefix(pktAuthChallenge, 100, 0, 2, uint64(0x87654321)<<32|2, 1, packetFlagControlAuthV1)
	tampered := append(append([]byte{}, secondPrefix...), payload...)
	tampered = append(tampered, ctx.tag(secondPrefix, payload)...)
	tampered[len(secondPrefix)] ^= 0x01
	parsed, ok = parsePacket(tampered)
	if !ok {
		t.Fatal("parse tampered packet")
	}
	if ctx.verifyRelayPacket(parsed) {
		t.Fatal("accepted tampered control packet")
	}
}

func decodeControlAuthHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

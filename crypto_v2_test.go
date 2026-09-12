package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESGCMV2AuthenticatesPacketHeader(t *testing.T) {
	const (
		channelID = uint32(1234)
		senderID  = uint32(5678)
		seq       = uint16(42)
	)

	plaintext := []byte{0x00, 0x2A, 0x11, 0x22, 0x33, 0x44}
	v2, err := newCryptoContext(cryptoAESGCMV2, "test-password", channelID)
	if err != nil {
		t.Fatalf("newCryptoContext(v2): %v", err)
	}

	base := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	counter := uint32(42)
	aad := buildAESGCMV2Packet(pktAudio, channelID, senderID, seq, base, counter, nil, nil)[:36]
	ciphertext, tag, err := v2.encryptV2(plaintext, base, counter, aad)
	if err != nil {
		t.Fatalf("encrypt(v2): %v", err)
	}
	v2Packet := buildAESGCMV2Packet(pktAudio, channelID, senderID, seq, base, counter, ciphertext, tag)

	parsed, ok := parsePacket(v2Packet)
	if !ok {
		t.Fatal("parsePacket(v2) failed")
	}
	if !bytes.Equal(parsed.AAD, aad) {
		t.Fatal("parsed packet AAD does not match the authenticated prefix")
	}
	decoded, err := v2.decryptV2(parsed.Payload, parsed.Tag, parsed.Sec.MediaNonceBase, parsed.Sec.MediaCounter, parsed.AAD)
	if err != nil {
		t.Fatalf("decrypt(v2): %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("plaintext mismatch: got %x want %x", decoded, plaintext)
	}

	if len(v2Packet) != 36+len(plaintext)+authTagSize {
		t.Fatalf("unexpected v2 packet size: %d", len(v2Packet))
	}
}

func TestPasswordKDFV1Vectors(t *testing.T) {
	key, err := derivePasswordKey("test-password", 1234)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("bcad701cf1a05f957d93aad27ea055a7d76f2d2650c89ab5bcb0790182854e4b")
	if !bytes.Equal(key, want) {
		t.Fatalf("argon2id password key = %x", key)
	}
	raw, err := derivePasswordKey("secret:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 1234)
	if err != nil {
		t.Fatal(err)
	}
	rawWant, _ := hex.DecodeString("a9c66a38294d3cb8e802cbde780c20fed61b8ef2663d44f6a1a8dab634566365")
	if !bytes.Equal(raw, rawWant) {
		t.Fatalf("raw-secret password key = %x", raw)
	}
	if _, err := derivePasswordKey("sha256:0011", 1234); err == nil {
		t.Fatal("sha256: credential was accepted")
	}
}

func TestMediaReplayWindow(t *testing.T) {
	s := &relaySession{mediaReplay: make(map[uint32]mediaReplayState)}
	base := [12]byte{1}
	if !s.acceptMediaCounter(1, base, 100) || !s.acceptMediaCounter(1, base, 99) || s.acceptMediaCounter(1, base, 99) {
		t.Fatal("replay window acceptance is incorrect")
	}
	if s.acceptMediaCounter(1, base, 36) {
		t.Fatal("stale counter was accepted")
	}
	if !s.acceptMediaCounter(1, base, 101) {
		t.Fatal("new counter was rejected")
	}
}

func TestAESGCMV2RejectsHeaderTampering(t *testing.T) {
	const (
		channelID = uint32(1234)
		senderID  = uint32(5678)
		seq       = uint16(42)
	)

	ctx, err := newCryptoContext(cryptoAESGCMV2, "test-password", channelID)
	if err != nil {
		t.Fatalf("newCryptoContext(v2): %v", err)
	}
	base := [12]byte{1}
	counter := uint32(99)
	aad := buildAESGCMV2Packet(pktAudio, channelID, senderID, seq, base, counter, nil, nil)[:36]
	ciphertext, tag, err := ctx.encryptV2([]byte("audio"), base, counter, aad)
	if err != nil {
		t.Fatalf("encrypt(v2): %v", err)
	}
	packet := buildAESGCMV2Packet(pktAudio, channelID, senderID, seq, base, counter, ciphertext, tag)

	// Channel ID is within the AAD. Changing one byte must invalidate the tag.
	packet[4] ^= 0x01
	parsed, ok := parsePacket(packet)
	if !ok {
		t.Fatal("parsePacket(tampered) failed")
	}
	if _, err := ctx.decryptV2(parsed.Payload, parsed.Tag, parsed.Sec.MediaNonceBase, parsed.Sec.MediaCounter, parsed.AAD); err == nil {
		t.Fatal("tampered v2 header was accepted")
	}
	if _, err := ctx.decryptV2(parsed.Payload, parsed.Tag, parsed.Sec.MediaNonceBase, parsed.Sec.MediaCounter, nil); err == nil {
		t.Fatal("v2 packet was accepted without its authenticated header")
	}
}

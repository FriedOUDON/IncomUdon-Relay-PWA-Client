package main

import (
	"bytes"
	"testing"
)

func TestAESGCMV2AuthenticatesPacketHeaderWithoutSizeGrowth(t *testing.T) {
	const (
		channelID = uint32(1234)
		senderID  = uint32(5678)
		seq       = uint16(42)
		nonce     = uint64(0x0102030405060708)
	)

	plaintext := []byte{0x00, 0x2A, 0x11, 0x22, 0x33, 0x44}
	v2, err := newCryptoContext(cryptoAESGCMV2, "test-password", channelID)
	if err != nil {
		t.Fatalf("newCryptoContext(v2): %v", err)
	}

	flags := packetFlagAESGCMV2HeaderAAD
	aad := securePacketAAD(pktAudio, channelID, senderID, seq, nonce, v2.keyID, flags)
	ciphertext, tag, err := v2.encrypt(plaintext, nonce, aad)
	if err != nil {
		t.Fatalf("encrypt(v2): %v", err)
	}
	v2Packet := buildEncryptedPacket(pktAudio, channelID, senderID, seq, nonce, v2.keyID, flags, ciphertext, tag)

	parsed, ok := parsePacket(v2Packet)
	if !ok {
		t.Fatal("parsePacket(v2) failed")
	}
	if !bytes.Equal(parsed.AAD, aad) {
		t.Fatal("parsed packet AAD does not match the authenticated prefix")
	}
	decoded, err := v2.decrypt(parsed.Payload, parsed.Tag, parsed.Sec.Nonce, parsed.AAD)
	if err != nil {
		t.Fatalf("decrypt(v2): %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("plaintext mismatch: got %x want %x", decoded, plaintext)
	}

	legacy, err := newCryptoContext(cryptoAESGCM, "test-password", channelID)
	if err != nil {
		t.Fatalf("newCryptoContext(legacy): %v", err)
	}
	legacyCiphertext, legacyTag, err := legacy.encrypt(plaintext, nonce, nil)
	if err != nil {
		t.Fatalf("encrypt(legacy): %v", err)
	}
	legacyPacket := buildEncryptedPacket(pktAudio, channelID, senderID, seq, nonce, legacy.keyID, 0, legacyCiphertext, legacyTag)
	if len(v2Packet) != len(legacyPacket) {
		t.Fatalf("v2 packet changed wire size: got %d want %d", len(v2Packet), len(legacyPacket))
	}
}

func TestAESGCMV2RejectsHeaderTampering(t *testing.T) {
	const (
		channelID = uint32(1234)
		senderID  = uint32(5678)
		seq       = uint16(42)
		nonce     = uint64(99)
	)

	ctx, err := newCryptoContext(cryptoAESGCMV2, "test-password", channelID)
	if err != nil {
		t.Fatalf("newCryptoContext(v2): %v", err)
	}
	flags := packetFlagAESGCMV2HeaderAAD
	aad := securePacketAAD(pktAudio, channelID, senderID, seq, nonce, ctx.keyID, flags)
	ciphertext, tag, err := ctx.encrypt([]byte("audio"), nonce, aad)
	if err != nil {
		t.Fatalf("encrypt(v2): %v", err)
	}
	packet := buildEncryptedPacket(pktAudio, channelID, senderID, seq, nonce, ctx.keyID, flags, ciphertext, tag)

	// Channel ID is within the AAD. Changing one byte must invalidate the tag.
	packet[4] ^= 0x01
	parsed, ok := parsePacket(packet)
	if !ok {
		t.Fatal("parsePacket(tampered) failed")
	}
	if _, err := ctx.decrypt(parsed.Payload, parsed.Tag, parsed.Sec.Nonce, parsed.AAD); err == nil {
		t.Fatal("tampered v2 header was accepted")
	}
	if _, err := ctx.decrypt(parsed.Payload, parsed.Tag, parsed.Sec.Nonce, nil); err == nil {
		t.Fatal("v2 packet was accepted without its authenticated header")
	}
}

package main

import (
	"bytes"
	"testing"
)

func TestVersion1MTULimits(t *testing.T) {
	if maxUDPDatagramBytes != 1200 || maxTransmitMediaFrameBytes != 1139 || maxMediaFrameBytes != 4096 {
		t.Fatalf("unexpected MTU constants: datagram=%d tx=%d rx=%d", maxUDPDatagramBytes, maxTransmitMediaFrameBytes, maxMediaFrameBytes)
	}

	ctx, err := newCryptoContext(cryptoAESGCMV2, "test-password", 100)
	if err != nil {
		t.Fatalf("new crypto context: %v", err)
	}
	frame := bytes.Repeat([]byte{0x55}, maxTransmitMediaFrameBytes)
	payload := append([]byte{0, 1}, frame...)
	flags := packetFlagAESGCMV2HeaderAAD
	aad := securePacketAAD(pktAudio, 100, 1001, 1, 1, ctx.keyID, flags)
	ciphertext, tag, err := ctx.encrypt(payload, 1, aad)
	if err != nil {
		t.Fatalf("encrypt audio: %v", err)
	}
	packet := buildEncryptedPacket(pktAudio, 100, 1001, 1, 1, ctx.keyID, flags, ciphertext, tag)
	if len(packet) != 1185 {
		t.Fatalf("max audio datagram = %d, want 1185", len(packet))
	}
	if len(packet) > maxUDPDatagramBytes {
		t.Fatalf("max audio datagram exceeds limit: %d", len(packet))
	}

	parity := fecParityPacket{
		BlockStart:   1,
		BlockSize:    6,
		ParityIndex:  0,
		FrameLengths: []uint16{1139, 1139, 1139, 1139, 1139, 1139},
		Data:         bytes.Repeat([]byte{0xaa}, maxTransmitMediaFrameBytes),
	}
	fecPayload, ok := parity.MarshalPayload()
	if !ok {
		t.Fatal("failed to marshal maximum FEC parity")
	}
	fecAAD := securePacketAAD(pktFec, 100, 1001, 2, 2, ctx.keyID, flags)
	fecCiphertext, fecTag, err := ctx.encrypt(fecPayload, 2, fecAAD)
	if err != nil {
		t.Fatalf("encrypt FEC: %v", err)
	}
	fecPacket := buildEncryptedPacket(pktFec, 100, 1001, 2, 2, ctx.keyID, flags, fecCiphertext, fecTag)
	if len(fecPacket) != maxUDPDatagramBytes {
		t.Fatalf("max FEC datagram = %d, want %d", len(fecPacket), maxUDPDatagramBytes)
	}
}

func TestCodecConfigV1FECNegotiation(t *testing.T) {
	s := &relaySession{
		cfg:         sessionConfig{ChannelID: 100, SenderID: 1001, FecEnabled: true, TxCodec: txCodecPCM},
		peerCodec:   make(map[uint32]peerCodecConfig),
		fecDecoders: make(map[uint32]*fecDecoder),
	}
	pkt := parsedPacket{Header: packetHeader{SenderID: 1002}, Payload: []byte{0, codecTransportOpus, 0, 16, codecConfigFECExternalParity | codecConfigFECExternalV2}}
	s.handleCodecConfig(pkt)
	if !s.fecReceiveEnabled(1002) {
		t.Fatal("valid external FEC v2 negotiation was not accepted")
	}
	pkt.Payload[4] = codecConfigFECExternalParity
	s.handleCodecConfig(pkt)
	if s.fecReceiveEnabled(1002) {
		t.Fatal("external FEC without v2 flag was accepted")
	}
}

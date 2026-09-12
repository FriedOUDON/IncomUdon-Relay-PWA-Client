package main

import (
	"bytes"
	"testing"
)

func TestVersion1MTULimits(t *testing.T) {
	if maxUDPDatagramBytes != 1200 || maxTransmitMediaFrameBytes != 1131 || maxMediaFrameBytes != 4096 {
		t.Fatalf("unexpected MTU constants: datagram=%d tx=%d rx=%d", maxUDPDatagramBytes, maxTransmitMediaFrameBytes, maxMediaFrameBytes)
	}

	ctx, err := newCryptoContext(cryptoAESGCMV2, "test-password", 100)
	if err != nil {
		t.Fatalf("new crypto context: %v", err)
	}
	frame := bytes.Repeat([]byte{0x55}, maxTransmitMediaFrameBytes)
	payload := append([]byte{0, 1}, frame...)
	base := [12]byte{1}
	aad := buildAESGCMV2Packet(pktAudio, 100, 1001, 1, base, 1, nil, nil)[:36]
	ciphertext, tag, err := ctx.encryptV2(payload, base, 1, aad)
	if err != nil {
		t.Fatalf("encrypt audio: %v", err)
	}
	packet := buildAESGCMV2Packet(pktAudio, 100, 1001, 1, base, 1, ciphertext, tag)
	if len(packet) != 36+len(payload)+authTagSize {
		t.Fatalf("max audio datagram = %d", len(packet))
	}
	if len(packet) > maxUDPDatagramBytes {
		t.Fatalf("max audio datagram exceeds limit: %d", len(packet))
	}

	parity := fecParityPacket{
		BlockStart:   1,
		BlockSize:    6,
		ParityIndex:  0,
		FrameLengths: []uint16{1131, 1131, 1131, 1131, 1131, 1131},
		Data:         bytes.Repeat([]byte{0xaa}, maxTransmitMediaFrameBytes),
	}
	fecPayload, ok := parity.MarshalPayload()
	if !ok {
		t.Fatal("failed to marshal maximum FEC parity")
	}
	fecAAD := buildAESGCMV2Packet(pktFec, 100, 1001, 2, base, 2, nil, nil)[:36]
	fecCiphertext, fecTag, err := ctx.encryptV2(fecPayload, base, 2, fecAAD)
	if err != nil {
		t.Fatalf("encrypt FEC: %v", err)
	}
	fecPacket := buildAESGCMV2Packet(pktFec, 100, 1001, 2, base, 2, fecCiphertext, fecTag)
	if len(fecPacket) > maxUDPDatagramBytes {
		t.Fatalf("max FEC datagram = %d exceeds MTU", len(fecPacket))
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

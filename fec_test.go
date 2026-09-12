package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestFECV2VariableFrameVector(t *testing.T) {
	frames := [][]byte{
		mustDecodeHex(t, "1020"),
		mustDecodeHex(t, "304050"),
		mustDecodeHex(t, "60708090"),
		mustDecodeHex(t, "a0"),
		mustDecodeHex(t, "b0c0d0e0f0"),
		mustDecodeHex(t, "010203040506"),
	}
	encoder := newFECEncoder(true)
	var parity []fecParityPacket
	for index, frame := range frames {
		parity = encoder.AddFrame(uint16(42+index), frame)
	}
	if len(parity) != 2 {
		t.Fatalf("parity count = %d, want 2", len(parity))
	}

	wantPayload := []string{
		"02002a060000020003000400010005000651d20374f506",
		"02002a06010002000300040001000500066ba17b5c1bc0",
	}
	for index, packet := range parity {
		payload, ok := packet.MarshalPayload()
		if !ok {
			t.Fatalf("marshal parity %d failed", index)
		}
		if got := hex.EncodeToString(payload); got != wantPayload[index] {
			t.Fatalf("parity %d payload = %s, want %s", index, got, wantPayload[index])
		}
		parsed, ok := parseFECV2Payload(payload)
		if !ok || !bytes.Equal(parsed.Data, packet.Data) || !equalFECFrameLengths(parsed.FrameLengths, packet.FrameLengths) {
			t.Fatalf("parity %d did not round-trip", index)
		}
	}
}

func TestFECV2RecoversTwoMissingVariableFrames(t *testing.T) {
	frames := [][]byte{
		mustDecodeHex(t, "1020"),
		mustDecodeHex(t, "304050"),
		mustDecodeHex(t, "60708090"),
		mustDecodeHex(t, "a0"),
		mustDecodeHex(t, "b0c0d0e0f0"),
		mustDecodeHex(t, "010203040506"),
	}
	encoder := newFECEncoder(true)
	var parity []fecParityPacket
	for index, frame := range frames {
		parity = encoder.AddFrame(uint16(42+index), frame)
	}

	decoder := newFECDecoder(true)
	for _, index := range []int{0, 2, 3, 5} {
		output := decoder.PushData(uint16(42+index), frames[index])
		if len(output) != 1 || !bytes.Equal(output[0].Data, frames[index]) {
			t.Fatalf("original frame %d was not emitted immediately", index)
		}
	}
	if output := decoder.PushParity(parity[0]); len(output) != 0 {
		t.Fatalf("one parity packet recovered %d frames, want 0", len(output))
	}
	output := decoder.PushParity(parity[1])
	if len(output) != 2 {
		t.Fatalf("recovered frames = %d, want 2", len(output))
	}
	for _, frame := range output {
		index := int(frame.Seq - 42)
		if index != 1 && index != 4 {
			t.Fatalf("unexpected recovered sequence %d", frame.Seq)
		}
		if !bytes.Equal(frame.Data, frames[index]) {
			t.Fatalf("recovered frame %d mismatch", index)
		}
	}
}

func TestFECV2FlushesShortFinalBlock(t *testing.T) {
	frames := [][]byte{
		mustDecodeHex(t, "112233"),
		mustDecodeHex(t, "44"),
		mustDecodeHex(t, "55667788"),
	}
	encoder := newFECEncoder(true)
	for index, frame := range frames {
		if output := encoder.AddFrame(uint16(48+index), frame); len(output) != 0 {
			t.Fatalf("short block emitted before release")
		}
	}
	parity := encoder.Flush()
	if len(parity) != 2 {
		t.Fatalf("final parity count = %d, want 2", len(parity))
	}
	payload, ok := parity[0].MarshalPayload()
	if !ok {
		t.Fatal("failed to encode final parity")
	}
	if got, want := hex.EncodeToString(payload), "020030030000030001000400444488"; got != want {
		t.Fatalf("final P payload = %s, want %s", got, want)
	}

	decoder := newFECDecoder(true)
	decoder.PushData(48, frames[0])
	decoder.PushParity(parity[0])
	output := decoder.PushParity(parity[1])
	if len(output) != 2 || output[0].Seq != 49 || output[1].Seq != 50 {
		t.Fatalf("short block recovery = %#v", output)
	}
	if !bytes.Equal(output[0].Data, frames[1]) || !bytes.Equal(output[1].Data, frames[2]) {
		t.Fatal("short block recovery data mismatch")
	}
}

func TestFECV2RejectsInvalidParityMetadata(t *testing.T) {
	if _, ok := parseFECV2Payload([]byte{2, 0, 1, 0, 0}); ok {
		t.Fatal("accepted zero-sized FEC block")
	}
	if _, ok := parseFECV2Payload([]byte{1, 0, 1, 1, 0, 0, 1, 0}); ok {
		t.Fatal("accepted obsolete FEC v1 payload")
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return decoded
}

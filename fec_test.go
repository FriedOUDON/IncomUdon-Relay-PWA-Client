package main

import (
	"bytes"
	"testing"
)

func TestFECDecoderRecoversTwoMissingFrames(t *testing.T) {
	encoder := newFECEncoder(true)
	frames := make([][]byte, 6)
	var parity []fecParityPacket
	for index := range frames {
		frames[index] = bytes.Repeat([]byte{byte(index + 1)}, 12)
		parity = encoder.AddFrame(uint16(index), frames[index])
	}
	if len(parity) != 2 {
		t.Fatalf("expected two parity packets, got %d", len(parity))
	}

	decoder := newFECDecoder(true)
	var output []fecDecodedFrame
	for _, index := range []int{0, 2, 3, 5} {
		output = append(output, decoder.PushData(uint16(index), frames[index])...)
	}
	output = append(output, decoder.PushParity(parity[0].BlockStart, parity[0].BlockSize, parity[0].ParityIndex, parity[0].Data)...)
	output = append(output, decoder.PushParity(parity[1].BlockStart, parity[1].BlockSize, parity[1].ParityIndex, parity[1].Data)...)
	if len(output) != len(frames) {
		t.Fatalf("expected %d recovered frames, got %d", len(frames), len(output))
	}
	for index, frame := range output {
		if frame.Seq != uint16(index) {
			t.Fatalf("frame %d has sequence %d", index, frame.Seq)
		}
		if !bytes.Equal(frame.Data, frames[index]) {
			t.Fatalf("frame %d did not match the original", index)
		}
	}
}

func TestFECDecoderBypassesVariableFrameBlocks(t *testing.T) {
	decoder := newFECDecoder(true)
	if output := decoder.PushData(0, []byte{1, 2, 3}); len(output) != 0 {
		t.Fatalf("first frame should wait for a compatible FEC block")
	}
	output := decoder.PushData(1, []byte{4, 5})
	if len(output) != 2 {
		t.Fatalf("expected preserved frames after variable-sized input, got %d", len(output))
	}
	if output[0].Seq != 0 || output[1].Seq != 1 {
		t.Fatalf("unexpected output order: %d, %d", output[0].Seq, output[1].Seq)
	}
}

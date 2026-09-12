package main

import (
	"encoding/binary"
	"testing"
)

func TestMixPCMFramesUsesRootMeanSourceGain(t *testing.T) {
	frame := func(sample int16) []byte {
		out := make([]byte, pcmBytesPerFrame)
		for index := 0; index < pcmSamplesPerFrame; index++ {
			binary.LittleEndian.PutUint16(out[index*2:index*2+2], uint16(sample))
		}
		return out
	}
	gains := make(map[uint32]float64)
	first := mixPCMFrames(map[uint32][]byte{1: frame(12000)}, gains)
	if got := int16(binary.LittleEndian.Uint16(first[pcmBytesPerFrame-2:])); got != 12000 {
		t.Fatalf("one-source gain = %d, want 12000", got)
	}
	second := mixPCMFrames(map[uint32][]byte{1: frame(12000), 2: frame(12000)}, gains)
	got := int16(binary.LittleEndian.Uint16(second[pcmBytesPerFrame-2:]))
	if got < 16900 || got > 17100 {
		t.Fatalf("two-source gain = %d, want about 16971", got)
	}
}

func TestMixPCMFramesClampsPeak(t *testing.T) {
	frame := make([]byte, pcmBytesPerFrame)
	for index := 0; index < pcmSamplesPerFrame; index++ {
		binary.LittleEndian.PutUint16(frame[index*2:index*2+2], uint16(32767))
	}
	gains := make(map[uint32]float64)
	mixed := mixPCMFrames(map[uint32][]byte{1: frame, 2: frame, 3: frame, 4: frame}, gains)
	if got := int16(binary.LittleEndian.Uint16(mixed[pcmBytesPerFrame-2:])); got != 32767 {
		t.Fatalf("mixed peak = %d, want clamp 32767", got)
	}
}

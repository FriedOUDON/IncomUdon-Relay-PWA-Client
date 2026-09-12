package main

import (
	"encoding/binary"
	"sort"
	"sync"
)

const (
	fecFormatVersionV2 = 2
	fecBlockSize       = 6
	// FEC parity arrives after the source block. With the standard 80 ms
	// playout target, a reconstruction older than four nominal intervals is
	// stale and must not be injected after newer speech.
	fecRecoveryDeadlineFrames = 4
)

// fecParityPacket is the FEC v2 plaintext payload. FrameLengths allows parity
// over variable-size codec frames without leaking padded bytes to the decoder.
type fecParityPacket struct {
	BlockStart   uint16
	BlockSize    uint8
	ParityIndex  uint8
	FrameLengths []uint16
	Data         []byte
}

func (p fecParityPacket) MarshalPayload() ([]byte, bool) {
	if p.BlockSize == 0 || p.BlockSize > fecBlockSize || p.ParityIndex > 1 || len(p.FrameLengths) != int(p.BlockSize) {
		return nil, false
	}
	maxLength := 0
	for _, length := range p.FrameLengths {
		if length == 0 || int(length) > maxMediaFrameBytes {
			return nil, false
		}
		if int(length) > maxLength {
			maxLength = int(length)
		}
	}
	if len(p.Data) != maxLength {
		return nil, false
	}

	payload := make([]byte, 5+len(p.FrameLengths)*2+len(p.Data))
	payload[0] = fecFormatVersionV2
	binary.BigEndian.PutUint16(payload[1:3], p.BlockStart)
	payload[3] = p.BlockSize
	payload[4] = p.ParityIndex
	for index, length := range p.FrameLengths {
		binary.BigEndian.PutUint16(payload[5+index*2:7+index*2], length)
	}
	copy(payload[5+len(p.FrameLengths)*2:], p.Data)
	return payload, true
}

func parseFECV2Payload(payload []byte) (fecParityPacket, bool) {
	if len(payload) < 5 || payload[0] != fecFormatVersionV2 {
		return fecParityPacket{}, false
	}
	blockSize := payload[3]
	if blockSize == 0 || blockSize > fecBlockSize || payload[4] > 1 {
		return fecParityPacket{}, false
	}
	metadataLength := 5 + int(blockSize)*2
	if len(payload) < metadataLength {
		return fecParityPacket{}, false
	}

	lengths := make([]uint16, blockSize)
	maxLength := 0
	for index := range lengths {
		length := binary.BigEndian.Uint16(payload[5+index*2 : 7+index*2])
		if length == 0 || int(length) > maxMediaFrameBytes {
			return fecParityPacket{}, false
		}
		lengths[index] = length
		if int(length) > maxLength {
			maxLength = int(length)
		}
	}
	if len(payload) != metadataLength+maxLength {
		return fecParityPacket{}, false
	}

	return fecParityPacket{
		BlockStart:   binary.BigEndian.Uint16(payload[1:3]),
		BlockSize:    blockSize,
		ParityIndex:  payload[4],
		FrameLengths: lengths,
		Data:         append([]byte(nil), payload[metadataLength:]...),
	}, true
}

type fecEncoder struct {
	mu sync.Mutex

	enabled    bool
	blockStart uint16
	nextSeq    uint16
	frames     [][]byte
}

func newFECEncoder(enabled bool) *fecEncoder {
	return &fecEncoder{enabled: enabled}
}

func (f *fecEncoder) SetEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enabled == enabled {
		return
	}
	f.enabled = enabled
	f.resetLocked()
}

func (f *fecEncoder) Enabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled
}

func (f *fecEncoder) Reset() {
	f.mu.Lock()
	f.resetLocked()
	f.mu.Unlock()
}

// AddFrame returns completed parity blocks. A sequence discontinuity closes the
// previous block so it cannot be mixed with unrelated media.
func (f *fecEncoder) AddFrame(audioSeq uint16, frame []byte) []fecParityPacket {
	if len(frame) == 0 || len(frame) > maxTransmitMediaFrameBytes {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled {
		return nil
	}

	var out []fecParityPacket
	if len(f.frames) > 0 && audioSeq != f.nextSeq {
		out = append(out, f.emitLocked()...)
	}
	if len(f.frames) == 0 {
		f.blockStart = audioSeq
	}
	f.frames = append(f.frames, append([]byte(nil), frame...))
	f.nextSeq = audioSeq + 1
	if len(f.frames) == fecBlockSize {
		out = append(out, f.emitLocked()...)
	}
	return out
}

// Flush emits P and Q for a final short block. It is called before PTT_OFF so
// the Relay still accepts the protected media stream.
func (f *fecEncoder) Flush() []fecParityPacket {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled {
		return nil
	}
	return f.emitLocked()
}

func (f *fecEncoder) emitLocked() []fecParityPacket {
	if len(f.frames) == 0 {
		return nil
	}

	lengths := make([]uint16, len(f.frames))
	maxLength := 0
	for index, frame := range f.frames {
		if len(frame) == 0 || len(frame) > maxTransmitMediaFrameBytes {
			f.resetLocked()
			return nil
		}
		lengths[index] = uint16(len(frame))
		if len(frame) > maxLength {
			maxLength = len(frame)
		}
	}

	p := make([]byte, maxLength)
	q := make([]byte, maxLength)
	fecGFInit()
	for index, frame := range f.frames {
		fecXorBytes(p, frame)
		fecXorMulBytes(q, frame, fecGFPow2(index))
	}

	blockStart := f.blockStart
	blockSize := uint8(len(f.frames))
	f.resetLocked()
	return []fecParityPacket{
		{BlockStart: blockStart, BlockSize: blockSize, ParityIndex: 0, FrameLengths: append([]uint16(nil), lengths...), Data: p},
		{BlockStart: blockStart, BlockSize: blockSize, ParityIndex: 1, FrameLengths: append([]uint16(nil), lengths...), Data: q},
	}
}

func (f *fecEncoder) resetLocked() {
	f.blockStart = 0
	f.nextSeq = 0
	f.frames = nil
}

var (
	fecGFOnce sync.Once
	fecGFExp  [512]byte
	fecGFLog  [256]byte
)

func fecGFInit() {
	fecGFOnce.Do(func() {
		x := 1
		for i := 0; i < 255; i++ {
			fecGFExp[i] = byte(x)
			fecGFLog[byte(x)] = byte(i)
			x <<= 1
			if x&0x100 != 0 {
				x ^= 0x11d
			}
		}
		for i := 255; i < 512; i++ {
			fecGFExp[i] = fecGFExp[i-255]
		}
		fecGFLog[0] = 0
	})
}

func fecGFMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return fecGFExp[int(fecGFLog[a])+int(fecGFLog[b])]
}

func fecGFPow2(exp int) byte {
	exp %= 255
	if exp < 0 {
		exp += 255
	}
	return fecGFExp[exp]
}

func fecXorBytes(dst []byte, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i]
	}
}

func fecXorMulBytes(dst []byte, src []byte, factor byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= fecGFMul(src[i], factor)
	}
}

type fecDecodedFrame struct {
	Seq  uint16
	Data []byte
}

type fecDecodeBlock struct {
	start         uint16
	lengths       []uint16
	data          [][]byte
	present       []bool
	parity        [2][]byte
	parityPresent [2]bool
}

// fecDecoder emits original frames immediately and keeps only a bounded cache
// for opportunistic recovery. This avoids adding a six-frame delay to normal
// speech merely because external FEC is enabled.
type fecDecoder struct {
	mu sync.Mutex

	enabled   bool
	blocks    map[uint16]*fecDecodeBlock
	pending   map[uint16][]byte
	emitted   map[uint16]struct{}
	latest    uint16
	hasLatest bool
}

func newFECDecoder(enabled bool) *fecDecoder {
	return &fecDecoder{
		enabled: enabled,
		blocks:  make(map[uint16]*fecDecodeBlock),
		pending: make(map[uint16][]byte),
		emitted: make(map[uint16]struct{}),
	}
}

func (f *fecDecoder) SetEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enabled == enabled {
		return
	}
	f.enabled = enabled
	f.resetLocked()
}

func (f *fecDecoder) Reset() {
	f.mu.Lock()
	f.resetLocked()
	f.mu.Unlock()
}

func (f *fecDecoder) PushData(audioSeq uint16, frame []byte) []fecDecodedFrame {
	if len(frame) == 0 || len(frame) > maxMediaFrameBytes {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled {
		return []fecDecodedFrame{{Seq: audioSeq, Data: append([]byte(nil), frame...)}}
	}

	f.pending[audioSeq] = append([]byte(nil), frame...)
	if !f.hasLatest || int16(audioSeq-f.latest) > 0 {
		f.latest = audioSeq
		f.hasLatest = true
	}
	var out []fecDecodedFrame
	if _, alreadyEmitted := f.emitted[audioSeq]; !alreadyEmitted {
		f.emitted[audioSeq] = struct{}{}
		out = append(out, fecDecodedFrame{Seq: audioSeq, Data: append([]byte(nil), frame...)})
	}

	for _, block := range f.blocks {
		index := fecBlockIndex(block, audioSeq)
		if index < 0 {
			continue
		}
		if len(frame) == int(block.lengths[index]) {
			block.data[index] = append([]byte(nil), frame...)
			block.present[index] = true
			out = append(out, f.recoverLocked(block)...)
		}
	}
	f.trimLocked(audioSeq)
	return sortFECFrames(out)
}

func (f *fecDecoder) PushParity(parity fecParityPacket) []fecDecodedFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled || parity.BlockSize == 0 || parity.BlockSize > fecBlockSize || parity.ParityIndex > 1 {
		return nil
	}
	if _, valid := parity.MarshalPayload(); !valid {
		return nil
	}

	block, ok := f.blocks[parity.BlockStart]
	if !ok {
		block = &fecDecodeBlock{
			start:   parity.BlockStart,
			lengths: append([]uint16(nil), parity.FrameLengths...),
			data:    make([][]byte, parity.BlockSize),
			present: make([]bool, parity.BlockSize),
		}
		for index := range block.lengths {
			seq := block.start + uint16(index)
			if frame, exists := f.pending[seq]; exists && len(frame) == int(block.lengths[index]) {
				block.data[index] = append([]byte(nil), frame...)
				block.present[index] = true
			}
		}
		f.blocks[block.start] = block
	} else if !equalFECFrameLengths(block.lengths, parity.FrameLengths) {
		return nil
	}

	block.parity[parity.ParityIndex] = append([]byte(nil), parity.Data...)
	block.parityPresent[parity.ParityIndex] = true
	out := f.recoverLocked(block)
	f.trimLocked(parity.BlockStart + uint16(parity.BlockSize))
	return sortFECFrames(out)
}

// Flush returns only recoverable missing frames. Original frames were emitted
// on arrival, so releasing a talker cannot replay an already rendered block.
func (f *fecDecoder) Flush() []fecDecodedFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fecDecodedFrame
	for _, block := range f.blocks {
		out = append(out, f.recoverLocked(block)...)
	}
	f.resetLocked()
	return sortFECFrames(out)
}

func (f *fecDecoder) resetLocked() {
	f.blocks = make(map[uint16]*fecDecodeBlock)
	f.pending = make(map[uint16][]byte)
	f.emitted = make(map[uint16]struct{})
	f.latest = 0
	f.hasLatest = false
}

func (f *fecDecoder) recoverLocked(block *fecDecodeBlock) []fecDecodedFrame {
	if block == nil || len(block.lengths) == 0 {
		return nil
	}
	missing := make([]int, 0, len(block.lengths))
	for index := range block.lengths {
		if !block.present[index] {
			missing = append(missing, index)
		}
	}
	if len(missing) == 0 || len(missing) > 2 || (!block.parityPresent[0] && !block.parityPresent[1]) || (len(missing) == 2 && (!block.parityPresent[0] || !block.parityPresent[1])) {
		return nil
	}

	maxLength := 0
	for _, length := range block.lengths {
		if int(length) > maxLength {
			maxLength = int(length)
		}
	}
	if maxLength == 0 {
		return nil
	}
	fecGFInit()
	sumP := make([]byte, maxLength)
	sumQ := make([]byte, maxLength)
	for index, frame := range block.data {
		if !block.present[index] {
			continue
		}
		fecXorBytes(sumP, frame)
		fecXorMulBytes(sumQ, frame, fecGFPow2(index))
	}

	recovered := make(map[int][]byte, len(missing))
	switch len(missing) {
	case 1:
		index := missing[0]
		frame := make([]byte, maxLength)
		if block.parityPresent[0] {
			copy(frame, block.parity[0])
			fecXorBytes(frame, sumP)
		} else {
			copy(frame, block.parity[1])
			fecXorBytes(frame, sumQ)
			coefficient := fecGFPow2(index)
			for offset := range frame {
				frame[offset] = fecGFDiv(frame[offset], coefficient)
			}
		}
		recovered[index] = frame[:block.lengths[index]]
	case 2:
		first, second := missing[0], missing[1]
		s := append([]byte(nil), block.parity[0]...)
		fecXorBytes(s, sumP)
		t := append([]byte(nil), block.parity[1]...)
		fecXorBytes(t, sumQ)
		firstCoefficient := fecGFPow2(first)
		secondCoefficient := fecGFPow2(second)
		denominator := firstCoefficient ^ secondCoefficient
		if denominator == 0 {
			return nil
		}
		firstFrame := make([]byte, maxLength)
		for offset := range firstFrame {
			numerator := t[offset] ^ fecGFMul(s[offset], secondCoefficient)
			firstFrame[offset] = fecGFDiv(numerator, denominator)
		}
		secondFrame := append([]byte(nil), firstFrame...)
		fecXorBytes(secondFrame, s)
		recovered[first] = firstFrame[:block.lengths[first]]
		recovered[second] = secondFrame[:block.lengths[second]]
	}

	out := make([]fecDecodedFrame, 0, len(recovered))
	for index, frame := range recovered {
		block.data[index] = append([]byte(nil), frame...)
		block.present[index] = true
		seq := block.start + uint16(index)
		if f.hasLatest && int16(f.latest-seq) > fecRecoveryDeadlineFrames {
			continue
		}
		if _, alreadyEmitted := f.emitted[seq]; alreadyEmitted {
			continue
		}
		f.emitted[seq] = struct{}{}
		out = append(out, fecDecodedFrame{Seq: seq, Data: append([]byte(nil), frame...)})
	}
	return out
}

func (f *fecDecoder) trimLocked(reference uint16) {
	const maxCachedSequences = 96
	for sequence := range f.pending {
		if int16(reference-sequence) > maxCachedSequences {
			delete(f.pending, sequence)
		}
	}
	for sequence := range f.emitted {
		if int16(reference-sequence) > maxCachedSequences {
			delete(f.emitted, sequence)
		}
	}
	for start := range f.blocks {
		if int16(reference-start) > maxCachedSequences {
			delete(f.blocks, start)
		}
	}
}

func fecBlockIndex(block *fecDecodeBlock, sequence uint16) int {
	if block == nil {
		return -1
	}
	index := int(uint16(sequence - block.start))
	if index >= len(block.lengths) {
		return -1
	}
	return index
}

func equalFECFrameLengths(first, second []uint16) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func sortFECFrames(frames []fecDecodedFrame) []fecDecodedFrame {
	sort.Slice(frames, func(i, j int) bool {
		return int16(frames[i].Seq-frames[j].Seq) < 0
	})
	return frames
}

func fecGFDiv(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	diff := int(fecGFLog[a]) - int(fecGFLog[b])
	if diff < 0 {
		diff += 255
	}
	return fecGFExp[diff]
}

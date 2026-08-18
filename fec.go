package main

import (
	"sort"
	"sync"
)

type fecParityPacket struct {
	BlockStart  uint16
	BlockSize   uint8
	ParityIndex uint8
	Data        []byte
}

type fecEncoder struct {
	mu sync.Mutex

	enabled   bool
	blockSize int
	frameSize int

	blockStart uint16
	inBlock    int
	parityP    []byte
	parityQ    []byte
}

func newFECEncoder(enabled bool) *fecEncoder {
	return &fecEncoder{
		enabled:   enabled,
		blockSize: 6,
	}
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

func (f *fecEncoder) SetBlockSize(blockSize int) {
	if blockSize <= 0 {
		return
	}
	f.mu.Lock()
	if f.blockSize == blockSize {
		f.mu.Unlock()
		return
	}
	f.blockSize = blockSize
	f.resetLocked()
	f.mu.Unlock()
}

func (f *fecEncoder) BlockSize() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blockSize
}

func (f *fecEncoder) beginBlockLocked(blockStart uint16, frameSize int) {
	f.blockStart = blockStart
	f.inBlock = 0
	f.frameSize = frameSize
	f.parityP = make([]byte, frameSize)
	f.parityQ = make([]byte, frameSize)
}

func (f *fecEncoder) AddFrame(audioSeq uint16, frame []byte) []fecParityPacket {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.enabled || len(frame) == 0 || f.blockSize <= 0 {
		return nil
	}
	fecGFInit()

	index := int(audioSeq % uint16(f.blockSize))
	blockStart := audioSeq - uint16(index)
	frameSize := len(frame)

	if f.inBlock == 0 || frameSize != f.frameSize || blockStart != f.blockStart {
		f.beginBlockLocked(blockStart, frameSize)
	}

	fecXorBytes(f.parityP, frame)
	fecXorMulBytes(f.parityQ, frame, fecGFPow2(index))

	f.inBlock++
	if f.inBlock < f.blockSize {
		return nil
	}

	p := fecParityPacket{
		BlockStart:  f.blockStart,
		BlockSize:   uint8(f.blockSize),
		ParityIndex: 0,
		Data:        append([]byte(nil), f.parityP...),
	}
	q := fecParityPacket{
		BlockStart:  f.blockStart,
		BlockSize:   uint8(f.blockSize),
		ParityIndex: 1,
		Data:        append([]byte(nil), f.parityQ...),
	}

	f.inBlock = 0
	f.parityP = nil
	f.parityQ = nil
	return []fecParityPacket{p, q}
}

func (f *fecEncoder) resetLocked() {
	f.frameSize = 0
	f.blockStart = 0
	f.inBlock = 0
	f.parityP = nil
	f.parityQ = nil
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
	blockSize     int
	frameSize     int
	data          [][]byte
	present       []bool
	parity        [2][]byte
	parityPresent [2]bool
}

type fecDecoder struct {
	mu           sync.Mutex
	enabled      bool
	blockSize    int
	blocks       map[uint16]*fecDecodeBlock
	bypassBlocks map[uint16]bool
}

func newFECDecoder(enabled bool) *fecDecoder {
	return &fecDecoder{
		enabled:      enabled,
		blockSize:    6,
		blocks:       make(map[uint16]*fecDecodeBlock),
		bypassBlocks: make(map[uint16]bool),
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
	if len(frame) == 0 {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled || f.blockSize <= 0 {
		return nil
	}

	index := int(audioSeq % uint16(f.blockSize))
	blockStart := audioSeq - uint16(index)
	out := f.flushBeforeLocked(blockStart)
	f.clearBypassBeforeLocked(blockStart)
	if f.bypassBlocks[blockStart] {
		out = append(out, fecDecodedFrame{Seq: audioSeq, Data: append([]byte(nil), frame...)})
		return append(out, f.trimLocked()...)
	}
	if block := f.blocks[blockStart]; block != nil && block.frameSize != len(frame) {
		// Variable-sized frames cannot share a parity block. Preserve media rather
		// than delaying it for parity that can never reconstruct this block.
		out = append(out, f.takeBlockLocked(blockStart)...)
		f.bypassBlocks[blockStart] = true
		out = append(out, fecDecodedFrame{Seq: audioSeq, Data: append([]byte(nil), frame...)})
		return append(out, f.trimLocked()...)
	}
	block := f.ensureBlockLocked(blockStart, len(frame))
	if block == nil || index < 0 || index >= block.blockSize {
		return out
	}
	block.data[index] = append(block.data[index][:0], frame...)
	block.present[index] = true
	out = append(out, f.tryOutputBlockLocked(blockStart)...)
	return append(out, f.trimLocked()...)
}

func (f *fecDecoder) PushParity(blockStart uint16, blockSize uint8, parityIndex uint8, data []byte) []fecDecodedFrame {
	if len(data) == 0 || parityIndex > 1 {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled || int(blockSize) != f.blockSize || f.bypassBlocks[blockStart] {
		return nil
	}

	block := f.ensureBlockLocked(blockStart, len(data))
	if block == nil {
		return nil
	}
	block.parity[parityIndex] = append(block.parity[parityIndex][:0], data...)
	block.parityPresent[parityIndex] = true
	out := f.tryOutputBlockLocked(blockStart)
	return append(out, f.trimLocked()...)
}

// Flush emits received data when a speaker stops before a complete FEC block.
func (f *fecDecoder) Flush() []fecDecodedFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	starts := f.sortedBlockStartsLocked()
	out := make([]fecDecodedFrame, 0)
	for _, start := range starts {
		out = append(out, f.takeBlockLocked(start)...)
	}
	return out
}

func (f *fecDecoder) resetLocked() {
	f.blocks = make(map[uint16]*fecDecodeBlock)
	f.bypassBlocks = make(map[uint16]bool)
}

func (f *fecDecoder) ensureBlockLocked(blockStart uint16, frameSize int) *fecDecodeBlock {
	if frameSize <= 0 {
		return nil
	}
	if block, ok := f.blocks[blockStart]; ok && block.frameSize != frameSize {
		delete(f.blocks, blockStart)
	}
	if block, ok := f.blocks[blockStart]; ok {
		return block
	}

	block := &fecDecodeBlock{
		start:     blockStart,
		blockSize: f.blockSize,
		frameSize: frameSize,
		data:      make([][]byte, f.blockSize),
		present:   make([]bool, f.blockSize),
	}
	f.blocks[blockStart] = block
	return block
}

func (f *fecDecoder) tryOutputBlockLocked(blockStart uint16) []fecDecodedFrame {
	block := f.blocks[blockStart]
	if block == nil {
		return nil
	}

	missing := f.missingIndexesLocked(block)
	switch len(missing) {
	case 0:
		return f.takeBlockLocked(blockStart)
	case 1:
		if !block.parityPresent[0] && !block.parityPresent[1] {
			return nil
		}
	case 2:
		if !block.parityPresent[0] || !block.parityPresent[1] {
			return nil
		}
	default:
		return nil
	}

	if !f.recoverLocked(block, missing) {
		return nil
	}
	return f.takeBlockLocked(blockStart)
}

func (f *fecDecoder) recoverLocked(block *fecDecodeBlock, missing []int) bool {
	if block == nil || block.frameSize <= 0 {
		return false
	}
	fecGFInit()

	sumP := make([]byte, block.frameSize)
	sumQ := make([]byte, block.frameSize)
	for index := 0; index < block.blockSize; index++ {
		if !block.present[index] {
			continue
		}
		fecXorBytes(sumP, block.data[index])
		fecXorMulBytes(sumQ, block.data[index], fecGFPow2(index))
	}

	switch len(missing) {
	case 1:
		index := missing[0]
		recovered := make([]byte, block.frameSize)
		if block.parityPresent[0] {
			copy(recovered, block.parity[0])
			fecXorBytes(recovered, sumP)
		} else {
			copy(recovered, block.parity[1])
			fecXorBytes(recovered, sumQ)
			coefficient := fecGFPow2(index)
			for i := range recovered {
				recovered[i] = fecGFDiv(recovered[i], coefficient)
			}
		}
		block.data[index] = recovered
		block.present[index] = true
		return true
	case 2:
		first := missing[0]
		second := missing[1]
		s := append([]byte(nil), block.parity[0]...)
		fecXorBytes(s, sumP)
		t := append([]byte(nil), block.parity[1]...)
		fecXorBytes(t, sumQ)
		firstCoefficient := fecGFPow2(first)
		secondCoefficient := fecGFPow2(second)
		denominator := firstCoefficient ^ secondCoefficient
		if denominator == 0 {
			return false
		}
		firstData := make([]byte, block.frameSize)
		for i := range firstData {
			numerator := t[i] ^ fecGFMul(s[i], secondCoefficient)
			firstData[i] = fecGFDiv(numerator, denominator)
		}
		secondData := append([]byte(nil), firstData...)
		fecXorBytes(secondData, s)
		block.data[first] = firstData
		block.data[second] = secondData
		block.present[first] = true
		block.present[second] = true
		return true
	default:
		return false
	}
}

func (f *fecDecoder) missingIndexesLocked(block *fecDecodeBlock) []int {
	missing := make([]int, 0, block.blockSize)
	for index := 0; index < block.blockSize; index++ {
		if !block.present[index] {
			missing = append(missing, index)
		}
	}
	return missing
}

func (f *fecDecoder) takeBlockLocked(blockStart uint16) []fecDecodedFrame {
	block := f.blocks[blockStart]
	if block == nil {
		return nil
	}
	delete(f.blocks, blockStart)

	out := make([]fecDecodedFrame, 0, block.blockSize)
	for index := 0; index < block.blockSize; index++ {
		if !block.present[index] || len(block.data[index]) == 0 {
			continue
		}
		out = append(out, fecDecodedFrame{
			Seq:  block.start + uint16(index),
			Data: append([]byte(nil), block.data[index]...),
		})
	}
	return out
}

func (f *fecDecoder) flushBeforeLocked(blockStart uint16) []fecDecodedFrame {
	starts := f.sortedBlockStartsLocked()
	out := make([]fecDecodedFrame, 0)
	for _, start := range starts {
		if fecSeqBefore(start, blockStart) {
			out = append(out, f.takeBlockLocked(start)...)
		}
	}
	return out
}

func (f *fecDecoder) clearBypassBeforeLocked(blockStart uint16) {
	for start := range f.bypassBlocks {
		if fecSeqBefore(start, blockStart) {
			delete(f.bypassBlocks, start)
		}
	}
}

func (f *fecDecoder) trimLocked() []fecDecodedFrame {
	const maxBufferedBlocks = 24
	starts := f.sortedBlockStartsLocked()
	out := make([]fecDecodedFrame, 0)
	for len(starts) > maxBufferedBlocks {
		out = append(out, f.takeBlockLocked(starts[0])...)
		starts = starts[1:]
	}
	return out
}

func (f *fecDecoder) sortedBlockStartsLocked() []uint16 {
	starts := make([]uint16, 0, len(f.blocks))
	for start := range f.blocks {
		starts = append(starts, start)
	}
	sort.Slice(starts, func(i, j int) bool {
		return fecSeqBefore(starts[i], starts[j])
	})
	return starts
}

func fecSeqBefore(first, second uint16) bool {
	return first != second && int16(second-first) > 0
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

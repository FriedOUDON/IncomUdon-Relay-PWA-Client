package main

import (
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

//go:build !linux || !cgo

package main

import "fmt"

type opusDecoderEngine struct{}
type opusEncoderEngine struct{}

func newOpusDecoderEngine(libPath string, sampleRate int, channels int) (*opusDecoderEngine, error) {
	return nil, fmt.Errorf("opus decode is available only on linux with cgo")
}

func (o *opusDecoderEngine) Close() {}

func (o *opusDecoderEngine) LibraryPath() string {
	return ""
}

func (o *opusDecoderEngine) Decode(packet []byte) ([]byte, error) {
	return nil, fmt.Errorf("opus decode is not available")
}

func newOpusEncoderEngine(libPath string, sampleRate int, channels int) (*opusEncoderEngine, error) {
	return nil, fmt.Errorf("opus encode is available only on linux with cgo")
}

func (o *opusEncoderEngine) Close() {}

func (o *opusEncoderEngine) LibraryPath() string {
	return ""
}

func (o *opusEncoderEngine) Encode(pcm []byte) ([]byte, error) {
	return nil, fmt.Errorf("opus encode is not available")
}

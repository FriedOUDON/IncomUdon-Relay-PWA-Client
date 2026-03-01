//go:build !linux || !cgo

package main

import "fmt"

type codec2Engine struct{}

func newCodec2Engine(libPath string) (*codec2Engine, error) {
	return nil, fmt.Errorf("codec2 dynamic loading is available only on linux with cgo")
}

func (e *codec2Engine) Close() {}

func (e *codec2Engine) LibraryPath() string {
	return ""
}

func (e *codec2Engine) ABIVersion() int {
	return 0
}

func (e *codec2Engine) PCMBytesForMode(mode int) (int, error) {
	return 0, fmt.Errorf("codec2 is not available")
}

func (e *codec2Engine) Encode(mode int, pcm []byte) ([]byte, error) {
	return nil, fmt.Errorf("codec2 is not available")
}

func (e *codec2Engine) Decode(mode int, frame []byte) ([]byte, error) {
	return nil, fmt.Errorf("codec2 is not available")
}

func (e *codec2Engine) DecodeBySize(frame []byte) ([]byte, int, error) {
	return nil, 0, fmt.Errorf("codec2 is not available")
}

//go:build linux && cgo

package main

/*
#cgo linux LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef int opus_int32;
typedef short opus_int16;
typedef struct OpusDecoder OpusDecoder;
typedef struct OpusEncoder OpusEncoder;

typedef OpusDecoder* (*opus_decoder_create_fn)(opus_int32 Fs, int channels, int *error);
typedef void (*opus_decoder_destroy_fn)(OpusDecoder*);
typedef int (*opus_decode_fn)(OpusDecoder*, const unsigned char*, opus_int32, opus_int16*, int, int);

typedef OpusEncoder* (*opus_encoder_create_fn)(opus_int32 Fs, int channels, int application, int *error);
typedef void (*opus_encoder_destroy_fn)(OpusEncoder*);
typedef int (*opus_encode_fn)(OpusEncoder*, const opus_int16*, int, unsigned char*, opus_int32);

typedef const char* (*opus_strerror_fn)(int);

typedef struct {
    void* handle;
    opus_decoder_create_fn decoder_create_fn;
    opus_decoder_destroy_fn decoder_destroy_fn;
    opus_decode_fn decode_fn;
    opus_encoder_create_fn encoder_create_fn;
    opus_encoder_destroy_fn encoder_destroy_fn;
    opus_encode_fn encode_fn;
    opus_strerror_fn strerror_fn;
} opus_api;

static int opus_load_symbol(void* handle, const char* name, void** out, char* err, size_t errLen) {
    dlerror();
    void* sym = dlsym(handle, name);
    const char* dlErr = dlerror();
    if (dlErr != NULL) {
        snprintf(err, errLen, "missing symbol %s: %s", name, dlErr);
        return 0;
    }
    *out = sym;
    return 1;
}

static int opus_api_open(opus_api* api, const char* path, char* err, size_t errLen) {
    memset(api, 0, sizeof(*api));

    dlerror();
    api->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) {
        const char* dlErr = dlerror();
        snprintf(err, errLen, "dlopen failed: %s", dlErr ? dlErr : "unknown error");
        return 0;
    }

    if (!opus_load_symbol(api->handle, "opus_decoder_create", (void**)&api->decoder_create_fn, err, errLen) ||
        !opus_load_symbol(api->handle, "opus_decoder_destroy", (void**)&api->decoder_destroy_fn, err, errLen) ||
        !opus_load_symbol(api->handle, "opus_decode", (void**)&api->decode_fn, err, errLen) ||
        !opus_load_symbol(api->handle, "opus_encoder_create", (void**)&api->encoder_create_fn, err, errLen) ||
        !opus_load_symbol(api->handle, "opus_encoder_destroy", (void**)&api->encoder_destroy_fn, err, errLen) ||
        !opus_load_symbol(api->handle, "opus_encode", (void**)&api->encode_fn, err, errLen) ||
        !opus_load_symbol(api->handle, "opus_strerror", (void**)&api->strerror_fn, err, errLen)) {
        dlclose(api->handle);
        memset(api, 0, sizeof(*api));
        return 0;
    }

    return 1;
}

static void opus_api_close(opus_api* api) {
    if (api->handle != NULL) {
        dlclose(api->handle);
    }
    memset(api, 0, sizeof(*api));
}

static OpusDecoder* opus_api_decoder_create(opus_api* api, int sampleRate, int channels, int* errCode) {
    if (api->decoder_create_fn == NULL) {
        if (errCode != NULL) {
            *errCode = -1;
        }
        return NULL;
    }
    return api->decoder_create_fn(sampleRate, channels, errCode);
}

static void opus_api_decoder_destroy(opus_api* api, OpusDecoder* decoder) {
    if (api->decoder_destroy_fn != NULL && decoder != NULL) {
        api->decoder_destroy_fn(decoder);
    }
}

static int opus_api_decode(opus_api* api, OpusDecoder* decoder, const unsigned char* data, int len, opus_int16* pcm, int frameSize, int decodeFec) {
    if (api->decode_fn == NULL || decoder == NULL) {
        return -1;
    }
    return api->decode_fn(decoder, data, len, pcm, frameSize, decodeFec);
}

static OpusEncoder* opus_api_encoder_create(opus_api* api, int sampleRate, int channels, int application, int* errCode) {
    if (api->encoder_create_fn == NULL) {
        if (errCode != NULL) {
            *errCode = -1;
        }
        return NULL;
    }
    return api->encoder_create_fn(sampleRate, channels, application, errCode);
}

static void opus_api_encoder_destroy(opus_api* api, OpusEncoder* encoder) {
    if (api->encoder_destroy_fn != NULL && encoder != NULL) {
        api->encoder_destroy_fn(encoder);
    }
}

static int opus_api_encode(opus_api* api, OpusEncoder* encoder, const opus_int16* pcm, int frameSize, unsigned char* data, opus_int32 maxDataBytes) {
    if (api->encode_fn == NULL || encoder == NULL) {
        return -1;
    }
    return api->encode_fn(encoder, pcm, frameSize, data, maxDataBytes);
}

static const char* opus_api_strerror(opus_api* api, int code) {
    if (api->strerror_fn == NULL) {
        return "unknown opus error";
    }
    return api->strerror_fn(code);
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

const (
	opusApplicationVoIP = 2048
	opusFrameDurationMs = 20
	opusMaxPacketBytes  = 1275
)

type opusDecoderEngine struct {
	mu sync.Mutex

	api        C.opus_api
	decoder    *C.OpusDecoder
	path       string
	sampleRate int
	channels   int
	maxSamples int
}

type opusEncoderEngine struct {
	mu sync.Mutex

	api          C.opus_api
	encoder      *C.OpusEncoder
	path         string
	sampleRate   int
	channels     int
	frameSamples int
	maxPacketLen int
}

func newOpusDecoderEngine(libPath string, sampleRate int, channels int) (*opusDecoderEngine, error) {
	if sampleRate <= 0 {
		sampleRate = 8000
	}
	if channels <= 0 {
		channels = 1
	}

	api, path, err := openOpusAPI(libPath)
	if err != nil {
		return nil, err
	}

	errCode := C.int(0)
	decoder := C.opus_api_decoder_create(&api, C.int(sampleRate), C.int(channels), &errCode)
	if decoder == nil {
		errStr := C.GoString(C.opus_api_strerror(&api, errCode))
		C.opus_api_close(&api)
		return nil, fmt.Errorf("opus_decoder_create failed: %s (%d)", errStr, int(errCode))
	}

	engine := &opusDecoderEngine{
		api:        api,
		decoder:    decoder,
		path:       path,
		sampleRate: sampleRate,
		channels:   channels,
		maxSamples: sampleRate * 120 / 1000,
	}
	if engine.maxSamples < 160 {
		engine.maxSamples = 160
	}

	return engine, nil
}

func newOpusEncoderEngine(libPath string, sampleRate int, channels int) (*opusEncoderEngine, error) {
	if sampleRate <= 0 {
		sampleRate = 8000
	}
	if channels <= 0 {
		channels = 1
	}

	api, path, err := openOpusAPI(libPath)
	if err != nil {
		return nil, err
	}

	errCode := C.int(0)
	encoder := C.opus_api_encoder_create(&api, C.int(sampleRate), C.int(channels), C.int(opusApplicationVoIP), &errCode)
	if encoder == nil {
		errStr := C.GoString(C.opus_api_strerror(&api, errCode))
		C.opus_api_close(&api)
		return nil, fmt.Errorf("opus_encoder_create failed: %s (%d)", errStr, int(errCode))
	}

	frameSamples := sampleRate * opusFrameDurationMs / 1000
	if frameSamples <= 0 {
		frameSamples = 160
	}

	engine := &opusEncoderEngine{
		api:          api,
		encoder:      encoder,
		path:         path,
		sampleRate:   sampleRate,
		channels:     channels,
		frameSamples: frameSamples,
		maxPacketLen: opusMaxPacketBytes,
	}
	if engine.maxPacketLen < 256 {
		engine.maxPacketLen = opusMaxPacketBytes
	}

	return engine, nil
}

func openOpusAPI(libPath string) (C.opus_api, string, error) {
	candidates := make([]string, 0, 16)
	path := strings.TrimSpace(libPath)
	if path != "" {
		candidates = append(candidates, path)
	} else {
		candidates = append(candidates, defaultOpusLibraryCandidates()...)
	}

	var api C.opus_api
	var openErr error
	tried := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		cPath := C.CString(candidate)
		errBuf := make([]C.char, 512)
		ok := C.opus_api_open(&api, cPath, &errBuf[0], C.size_t(len(errBuf)))
		C.free(unsafe.Pointer(cPath))
		if ok != 0 {
			path = candidate
			openErr = nil
			break
		}
		errText := C.GoString(&errBuf[0])
		tried = append(tried, fmt.Sprintf("%s (%s)", candidate, errText))
		openErr = fmt.Errorf("%s", errText)
	}

	if openErr != nil {
		if len(tried) == 0 {
			return api, "", fmt.Errorf("failed to load opus library: %w", openErr)
		}

		maxShown := 4
		shown := tried
		if len(tried) > maxShown {
			shown = append([]string{}, tried[:maxShown]...)
			shown = append(shown, fmt.Sprintf("... +%d more", len(tried)-maxShown))
		}

		hint := ""
		for _, item := range tried {
			if strings.Contains(item, "__memcpy_chk") {
				hint = " (detected glibc/musl mismatch; use musl-built libopus.so or Alpine package libopus)"
				break
			}
		}

		return api, "", fmt.Errorf(
			"failed to load opus library; set -opus-lib or INCOMUDON_OPUS_LIB%s (tried %d candidates: %s)",
			hint,
			len(tried),
			strings.Join(shown, "; "),
		)
	}

	return api, path, nil
}

func defaultOpusLibraryCandidates() []string {
	baseDirs := []string{
		"/opt/libopus",
		"third_party/libopus",
		"./third_party/libopus",
		"../third_party/libopus",
	}

	archDirs := []string{
		"linux-x86_64",
		"linux-aarch64",
		"linux-arm64",
		"linux-armv7l",
		"linux-raspi-armv7l",
		"linux-raspi-aarch64",
	}

	switch runtime.GOARCH {
	case "amd64":
		archDirs = append([]string{"linux-x86_64"}, archDirs...)
	case "arm64":
		archDirs = append([]string{"linux-raspi-aarch64", "linux-aarch64", "linux-arm64"}, archDirs...)
	case "arm":
		archDirs = append([]string{"linux-raspi-armv7l", "linux-armv7l"}, archDirs...)
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, len(baseDirs)*len(archDirs)*2+2)
	appendUnique := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}

	for _, baseDir := range baseDirs {
		for _, archDir := range archDirs {
			appendUnique(filepath.Clean(filepath.Join(baseDir, archDir, "libopus.so")))
			appendUnique(filepath.Clean(filepath.Join(baseDir, archDir, "libopus.so.0")))
		}
	}

	appendUnique("libopus.so.0")
	appendUnique("libopus.so")
	return out
}

func (o *opusDecoderEngine) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()

	C.opus_api_decoder_destroy(&o.api, o.decoder)
	o.decoder = nil
	C.opus_api_close(&o.api)
}

func (o *opusDecoderEngine) LibraryPath() string {
	return o.path
}

func (o *opusDecoderEngine) Decode(packet []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.decoder == nil {
		return nil, fmt.Errorf("opus decoder is not initialized")
	}
	if len(packet) == 0 {
		return nil, fmt.Errorf("empty opus packet")
	}

	pcm := make([]C.opus_int16, o.maxSamples*o.channels)
	decoded := C.opus_api_decode(
		&o.api,
		o.decoder,
		(*C.uchar)(unsafe.Pointer(&packet[0])),
		C.int(len(packet)),
		(*C.opus_int16)(unsafe.Pointer(&pcm[0])),
		C.int(o.maxSamples),
		C.int(0),
	)
	if decoded < 0 {
		errStr := C.GoString(C.opus_api_strerror(&o.api, C.int(decoded)))
		return nil, fmt.Errorf("opus decode failed: %s (%d)", errStr, int(decoded))
	}

	samples := int(decoded) * o.channels
	if samples <= 0 {
		return nil, fmt.Errorf("opus decoder returned no samples")
	}

	out := make([]byte, samples*2)
	for i := 0; i < samples; i++ {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], uint16(int16(pcm[i])))
	}
	return out, nil
}

func (o *opusEncoderEngine) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()

	C.opus_api_encoder_destroy(&o.api, o.encoder)
	o.encoder = nil
	C.opus_api_close(&o.api)
}

func (o *opusEncoderEngine) LibraryPath() string {
	return o.path
}

func (o *opusEncoderEngine) Encode(pcm []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.encoder == nil {
		return nil, fmt.Errorf("opus encoder is not initialized")
	}

	samplesPerFrame := o.frameSamples * o.channels
	if samplesPerFrame <= 0 {
		return nil, fmt.Errorf("invalid opus frame size")
	}

	normalized := make([]byte, samplesPerFrame*2)
	copy(normalized, pcm)

	input := make([]C.opus_int16, samplesPerFrame)
	for i := 0; i < samplesPerFrame; i++ {
		off := i * 2
		sample := int16(binary.LittleEndian.Uint16(normalized[off : off+2]))
		input[i] = C.opus_int16(sample)
	}

	out := make([]byte, o.maxPacketLen)
	encoded := C.opus_api_encode(
		&o.api,
		o.encoder,
		(*C.opus_int16)(unsafe.Pointer(&input[0])),
		C.int(o.frameSamples),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.opus_int32(len(out)),
	)
	if encoded < 0 {
		errStr := C.GoString(C.opus_api_strerror(&o.api, C.int(encoded)))
		return nil, fmt.Errorf("opus encode failed: %s (%d)", errStr, int(encoded))
	}
	if encoded == 0 {
		return nil, fmt.Errorf("opus encoder returned empty packet")
	}

	return append([]byte(nil), out[:int(encoded)]...), nil
}

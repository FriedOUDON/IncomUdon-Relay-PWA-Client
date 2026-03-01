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

typedef struct CODEC2 CODEC2;

typedef CODEC2* (*codec2_create_fn)(int);
typedef void (*codec2_destroy_fn)(CODEC2*);
typedef void (*codec2_encode_fn)(CODEC2*, unsigned char*, short*);
typedef void (*codec2_decode_fn)(CODEC2*, short*, const unsigned char*);
typedef int (*codec2_bits_per_frame_fn)(CODEC2*);
typedef int (*codec2_samples_per_frame_fn)(CODEC2*);
typedef int (*codec2_abi_version_fn)(void);

typedef struct {
    void* handle;
    codec2_create_fn create_fn;
    codec2_destroy_fn destroy_fn;
    codec2_encode_fn encode_fn;
    codec2_decode_fn decode_fn;
    codec2_bits_per_frame_fn bits_fn;
    codec2_samples_per_frame_fn samples_fn;
    codec2_abi_version_fn abi_fn;
} codec2_api;

static int codec2_load_symbol(void* handle, const char* name, void** out, char* err, size_t errLen) {
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

static int codec2_api_open(codec2_api* api, const char* path, char* err, size_t errLen) {
    memset(api, 0, sizeof(*api));

    dlerror();
    api->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) {
        const char* dlErr = dlerror();
        snprintf(err, errLen, "dlopen failed: %s", dlErr ? dlErr : "unknown error");
        return 0;
    }

    if (!codec2_load_symbol(api->handle, "codec2_create", (void**)&api->create_fn, err, errLen) ||
        !codec2_load_symbol(api->handle, "codec2_destroy", (void**)&api->destroy_fn, err, errLen) ||
        !codec2_load_symbol(api->handle, "codec2_encode", (void**)&api->encode_fn, err, errLen) ||
        !codec2_load_symbol(api->handle, "codec2_decode", (void**)&api->decode_fn, err, errLen) ||
        !codec2_load_symbol(api->handle, "codec2_bits_per_frame", (void**)&api->bits_fn, err, errLen) ||
        !codec2_load_symbol(api->handle, "codec2_samples_per_frame", (void**)&api->samples_fn, err, errLen) ||
        !codec2_load_symbol(api->handle, "incomudon_codec2_abi_version", (void**)&api->abi_fn, err, errLen)) {
        dlclose(api->handle);
        memset(api, 0, sizeof(*api));
        return 0;
    }

    return 1;
}

static void codec2_api_close(codec2_api* api) {
    if (api->handle != NULL) {
        dlclose(api->handle);
    }
    memset(api, 0, sizeof(*api));
}

static CODEC2* codec2_api_create(codec2_api* api, int mode) {
    if (api->create_fn == NULL) {
        return NULL;
    }
    return api->create_fn(mode);
}

static void codec2_api_destroy(codec2_api* api, CODEC2* state) {
    if (api->destroy_fn != NULL && state != NULL) {
        api->destroy_fn(state);
    }
}

static int codec2_api_bits_per_frame(codec2_api* api, CODEC2* state) {
    if (api->bits_fn == NULL || state == NULL) {
        return 0;
    }
    return api->bits_fn(state);
}

static int codec2_api_samples_per_frame(codec2_api* api, CODEC2* state) {
    if (api->samples_fn == NULL || state == NULL) {
        return 0;
    }
    return api->samples_fn(state);
}

static int codec2_api_abi_version(codec2_api* api) {
    if (api->abi_fn == NULL) {
        return 0;
    }
    return api->abi_fn();
}

static void codec2_api_encode(codec2_api* api, CODEC2* state, unsigned char* bits, short* speechIn) {
    if (api->encode_fn != NULL && state != NULL) {
        api->encode_fn(state, bits, speechIn);
    }
}

static void codec2_api_decode(codec2_api* api, CODEC2* state, short* speechOut, const unsigned char* bits) {
    if (api->decode_fn != NULL && state != NULL) {
        api->decode_fn(state, speechOut, bits);
    }
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

const (
	codec2Mode3200 = 0
	codec2Mode2400 = 1
	codec2Mode1600 = 2
	codec2Mode700C = 8
	codec2Mode450  = 10

	incomUdonCodec2ABIVersion = 2026022801
)

type codec2State struct {
	ptr        *C.CODEC2
	frameBytes int
	samples    int
}

type codec2Engine struct {
	mu sync.Mutex

	api        C.codec2_api
	path       string
	abiVersion int

	txStates map[int]*codec2State
	rxStates map[int]*codec2State
}

func newCodec2Engine(libPath string) (*codec2Engine, error) {
	candidates := make([]string, 0, 16)
	path := strings.TrimSpace(libPath)
	explicitPathProvided := path != ""
	if path != "" {
		candidates = append(candidates, path)
	} else {
		candidates = append(candidates, defaultCodec2LibraryCandidates()...)
	}

	var api C.codec2_api
	var openErr error
	tried := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}

		statErrText := ""
		statExists := false
		if strings.Contains(candidate, "/") {
			if _, statErr := os.Stat(candidate); statErr != nil {
				statErrText = statErr.Error()
			} else {
				statExists = true
			}
		}

		cPath := C.CString(candidate)
		errBuf := make([]C.char, 512)
		ok := C.codec2_api_open(&api, cPath, &errBuf[0], C.size_t(len(errBuf)))
		C.free(unsafe.Pointer(cPath))
		if ok != 0 {
			abiVersion := int(C.codec2_api_abi_version(&api))
			if abiVersion != incomUdonCodec2ABIVersion {
				C.codec2_api_close(&api)
				errText := fmt.Sprintf(
					"codec2 ABI mismatch (expected=%d got=%d)",
					incomUdonCodec2ABIVersion,
					abiVersion,
				)
				tried = append(tried, fmt.Sprintf("%s (%s)", candidate, errText))
				openErr = fmt.Errorf("%s", errText)
				continue
			}
			path = candidate
			engine := &codec2Engine{
				api:        api,
				path:       path,
				abiVersion: abiVersion,
				txStates:   make(map[int]*codec2State),
				rxStates:   make(map[int]*codec2State),
			}
			return engine, nil
		}
		errText := C.GoString(&errBuf[0])
		if statErrText != "" {
			errText = fmt.Sprintf("%s; stat=%s", errText, statErrText)
		} else if statExists && strings.Contains(strings.ToLower(errText), "no such file or directory") {
			errText = fmt.Sprintf("%s (file exists; dependent shared library or runtime loader may be missing)", errText)
		}
		tried = append(tried, fmt.Sprintf("%s (%s)", candidate, errText))
		openErr = fmt.Errorf("%s", errText)
	}
	if openErr != nil {
		if len(tried) == 0 {
			return nil, fmt.Errorf("failed to load codec2 library: %w", openErr)
		}

		maxShown := 4
		shown := tried
		if len(tried) > maxShown {
			shown = append([]string{}, tried[:maxShown]...)
			shown = append(shown, fmt.Sprintf("... +%d more", len(tried)-maxShown))
		}

		hint := ""
		for _, item := range tried {
			lower := strings.ToLower(item)
			switch {
			case strings.Contains(item, "stat="):
				hint = " (specified path is not visible from runtime; in Docker, use an in-container path or bind-mount it)"
			case strings.Contains(item, "__memcpy_chk"):
				hint = " (detected glibc/musl mismatch; use musl-built libcodec2.so on Alpine)"
			case strings.Contains(lower, "wrong elf class"), strings.Contains(lower, "exec format error"):
				hint = " (detected architecture mismatch; verify library arch matches runtime arch)"
			case strings.Contains(item, "No such file or directory"):
				hint = " (library file or dependent shared library is missing)"
			}
			if hint != "" {
				break
			}
		}
		if hint == "" && explicitPathProvided {
			hint = " (explicit path was provided but could not be opened; verify container path and dependent libraries)"
		}

		return nil, fmt.Errorf(
			"failed to load codec2 library; set -codec2-lib or INCOMUDON_CODEC2_LIB%s (tried %d candidates: %s)",
			hint,
			len(tried),
			strings.Join(shown, "; "),
		)
	}
	return nil, fmt.Errorf("failed to load codec2 library: no candidate path")
}

func defaultCodec2LibraryCandidates() []string {
	baseDirs := []string{
		"/opt/libcodec2",
		"/opt/codec2",
		"third_party/libcodec2",
		"./third_party/libcodec2",
		"../third_party/libcodec2",
	}

	archDirs := []string{
		"linux-musl-x86_64",
		"linux-musl-aarch64",
		"linux-musl-armv7l",
		"linux-x86_64",
		"linux-aarch64",
		"linux-arm64",
		"linux-armv7l",
		"linux-raspi-armv7l",
		"linux-raspi-aarch64",
	}

	switch runtime.GOARCH {
	case "amd64":
		archDirs = append([]string{"linux-musl-x86_64", "linux-x86_64"}, archDirs...)
	case "arm64":
		archDirs = append([]string{
			"linux-musl-aarch64",
			"linux-raspi-aarch64",
			"linux-aarch64",
			"linux-arm64",
		}, archDirs...)
	case "arm":
		archDirs = append([]string{
			"linux-musl-armv7l",
			"linux-raspi-armv7l",
			"linux-armv7l",
		}, archDirs...)
	}

	sharedObjects := []string{
		"libcodec2.so",
		"libcodec2-local.so",
		"libcodec2.so.1",
		"libcodec2.so.0",
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, len(baseDirs)*len(archDirs)*len(sharedObjects)+len(sharedObjects))
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
		for _, soName := range sharedObjects {
			appendUnique(filepath.Clean(filepath.Join(baseDir, soName)))
		}
		for _, archDir := range archDirs {
			for _, soName := range sharedObjects {
				appendUnique(filepath.Clean(filepath.Join(baseDir, archDir, soName)))
			}
		}
	}

	for _, soName := range []string{"libcodec2.so.1", "libcodec2.so.0", "libcodec2.so", "libcodec2-local.so"} {
		appendUnique(soName)
	}

	return out
}

func (e *codec2Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, st := range e.txStates {
		C.codec2_api_destroy(&e.api, st.ptr)
	}
	for _, st := range e.rxStates {
		C.codec2_api_destroy(&e.api, st.ptr)
	}
	e.txStates = map[int]*codec2State{}
	e.rxStates = map[int]*codec2State{}
	C.codec2_api_close(&e.api)
}

func (e *codec2Engine) LibraryPath() string {
	return e.path
}

func (e *codec2Engine) ABIVersion() int {
	return e.abiVersion
}

func (e *codec2Engine) PCMBytesForMode(mode int) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	bitrate := normalizeCodecMode(mode)
	state, err := e.ensureTxStateLocked(bitrate)
	if err != nil {
		return 0, err
	}
	pcmBytes := state.samples * 2
	if pcmBytes <= 0 {
		return 0, fmt.Errorf("invalid codec2 pcm bytes mode=%d samples=%d", bitrate, state.samples)
	}
	return pcmBytes, nil
}

func (e *codec2Engine) Encode(mode int, pcm []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	bitrate := normalizeCodecMode(mode)
	state, err := e.ensureTxStateLocked(bitrate)
	if err != nil {
		return nil, err
	}

	pcmBytes := state.samples * 2
	normalized := make([]byte, pcmBytes)
	copy(normalized, pcm)

	speech := make([]C.short, state.samples)
	for i := 0; i < state.samples; i++ {
		off := i * 2
		sample := int16(binary.LittleEndian.Uint16(normalized[off : off+2]))
		speech[i] = C.short(sample)
	}

	out := make([]byte, state.frameBytes)
	if len(out) == 0 {
		return nil, fmt.Errorf("codec2 mode=%d returned empty frame", bitrate)
	}
	C.codec2_api_encode(
		&e.api,
		state.ptr,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.short)(unsafe.Pointer(&speech[0])),
	)

	return out, nil
}

func (e *codec2Engine) Decode(mode int, frame []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	bitrate := normalizeCodecMode(mode)
	state, err := e.ensureRxStateLocked(bitrate)
	if err != nil {
		return nil, err
	}

	return e.decodeWithStateLocked(state, frame)
}

func (e *codec2Engine) DecodeBySize(frame []byte) ([]byte, int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidates := make([]int, 0, 2)
	for _, mode := range []int{450, 700, 1600, 2400, 3200} {
		state, err := e.ensureRxStateLocked(mode)
		if err != nil {
			continue
		}
		if state.frameBytes == len(frame) {
			candidates = append(candidates, mode)
		}
	}

	if len(candidates) == 0 {
		return nil, 0, fmt.Errorf("no codec2 mode matches frame bytes=%d", len(frame))
	}

	mode := candidates[0]
	state, err := e.ensureRxStateLocked(mode)
	if err != nil {
		return nil, 0, err
	}
	pcm, err := e.decodeWithStateLocked(state, frame)
	if err != nil {
		return nil, 0, err
	}
	return pcm, mode, nil
}

func (e *codec2Engine) ensureTxStateLocked(mode int) (*codec2State, error) {
	if st, ok := e.txStates[mode]; ok {
		return st, nil
	}
	st, err := e.createStateLocked(mode)
	if err != nil {
		return nil, err
	}
	e.txStates[mode] = st
	return st, nil
}

func (e *codec2Engine) ensureRxStateLocked(mode int) (*codec2State, error) {
	if st, ok := e.rxStates[mode]; ok {
		return st, nil
	}
	st, err := e.createStateLocked(mode)
	if err != nil {
		return nil, err
	}
	e.rxStates[mode] = st
	return st, nil
}

func (e *codec2Engine) createStateLocked(mode int) (*codec2State, error) {
	modeConst := codec2ModeConstant(mode)
	ptr := C.codec2_api_create(&e.api, C.int(modeConst))
	if ptr == nil {
		return nil, fmt.Errorf("codec2_create failed for mode=%d", mode)
	}

	bits := int(C.codec2_api_bits_per_frame(&e.api, ptr))
	samples := int(C.codec2_api_samples_per_frame(&e.api, ptr))
	if bits <= 0 || samples <= 0 {
		C.codec2_api_destroy(&e.api, ptr)
		return nil, fmt.Errorf("invalid codec2 frame params mode=%d bits=%d samples=%d", mode, bits, samples)
	}

	frameBytes := (bits + 7) / 8
	if frameBytes <= 0 {
		C.codec2_api_destroy(&e.api, ptr)
		return nil, fmt.Errorf("invalid codec2 frame bytes mode=%d bits=%d", mode, bits)
	}

	return &codec2State{
		ptr:        ptr,
		frameBytes: frameBytes,
		samples:    samples,
	}, nil
}

func (e *codec2Engine) decodeWithStateLocked(state *codec2State, frame []byte) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("codec2 state is nil")
	}

	buf := make([]byte, state.frameBytes)
	copy(buf, frame)

	speech := make([]C.short, state.samples)
	C.codec2_api_decode(
		&e.api,
		state.ptr,
		(*C.short)(unsafe.Pointer(&speech[0])),
		(*C.uchar)(unsafe.Pointer(&buf[0])),
	)

	pcm := make([]byte, state.samples*2)
	for i := 0; i < state.samples; i++ {
		off := i * 2
		sample := int16(speech[i])
		binary.LittleEndian.PutUint16(pcm[off:off+2], uint16(sample))
	}

	return pcm, nil
}

func codec2ModeConstant(mode int) int {
	switch normalizeCodecMode(mode) {
	case 450:
		return codec2Mode450
	case 700:
		return codec2Mode700C
	case 1600:
		return codec2Mode1600
	case 2400:
		return codec2Mode2400
	default:
		return codec2Mode3200
	}
}

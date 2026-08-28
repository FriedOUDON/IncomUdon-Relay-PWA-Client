package main

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedAudioWorklets(t *testing.T) {
	for _, name := range []string{
		"web/worklets/mic-capture-worklet.js",
		"web/worklets/pcm-playback-worklet.js",
		"web/worklets/audio-tx-pacer-worklet.js",
	} {
		info, err := fs.Stat(webAssets, name)
		if err != nil {
			t.Fatalf("embedded worklet %q: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("embedded worklet %q is empty", name)
		}
	}
}

func TestAudioFileDecodeUsesRelaySampleRate(t *testing.T) {
	contents, err := fs.ReadFile(webAssets, "web/app.js")
	if err != nil {
		t.Fatalf("read web/app.js: %v", err)
	}

	source := string(contents)
	for _, snippet := range []string{
		"const targetSampleRate = 8000;",
		"const decodeContext = new OfflineAudioContext(1, 1, targetSampleRate);",
		"const decoded = await decodeContext.decodeAudioData(sourceBytes.slice(0));",
	} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("audio-file decode path is missing %q", snippet)
		}
	}
	if strings.Contains(source, "const decodeContext = new AudioContextClass();") {
		t.Fatal("audio-file decode must not resample through a default AudioContext before 8 kHz rendering")
	}
}

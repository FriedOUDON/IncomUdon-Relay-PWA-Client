package main

import (
	"io/fs"
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

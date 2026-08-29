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

func TestSelfSenderMuteWebControl(t *testing.T) {
	index, err := fs.ReadFile(webAssets, "web/index.html")
	if err != nil {
		t.Fatalf("read web/index.html: %v", err)
	}
	if !strings.Contains(string(index), `id="selfSenderMute" type="checkbox" checked`) {
		t.Fatal("self sender mute control must be enabled by default")
	}

	app, err := fs.ReadFile(webAssets, "web/app.js")
	if err != nil {
		t.Fatalf("read web/app.js: %v", err)
	}
	for _, snippet := range []string{
		`selfMute: !!state.selfSenderMute,`,
		`type: "set_self_mute", selfMute: enabled`,
		`"receiveOnly", "selfSenderMute", "audioTxLoopEnabled"`,
	} {
		if !strings.Contains(string(app), snippet) {
			t.Fatalf("self sender mute client path is missing %q", snippet)
		}
	}
}

func TestSettingsExportsOmitPasswordHashButImportsAcceptIt(t *testing.T) {
	app, err := fs.ReadFile(webAssets, "web/app.js")
	if err != nil {
		t.Fatalf("read web/app.js: %v", err)
	}
	for _, snippet := range []string{
		`"relayHost", "relayPort", "directoryHost", "directoryPort", "channelId", "senderId", "passwordHash",`,
		`delete settings.passwordHash;`,
		`const value = documentData.settings[key];`,
	} {
		if !strings.Contains(string(app), snippet) {
			t.Fatalf("single-channel settings path is missing %q", snippet)
		}
	}

	multi, err := fs.ReadFile(webAssets, "web/multi.js")
	if err != nil {
		t.Fatalf("read web/multi.js: %v", err)
	}
	for _, snippet := range []string{
		`"relayHost", "relayPort", "directoryHost", "directoryPort", "channelId", "senderId", "passwordHash",`,
		`delete settings.passwordHash;`,
	} {
		if !strings.Contains(string(multi), snippet) {
			t.Fatalf("multi-channel settings path is missing %q", snippet)
		}
	}
}

func TestPacketDebugAssets(t *testing.T) {
	index, err := fs.ReadFile(webAssets, "web/index.html")
	if err != nil {
		t.Fatalf("read web/index.html: %v", err)
	}
	if !strings.Contains(string(index), `id="packetDebugCard"`) {
		t.Fatal("packet debug card is missing from the single-channel page")
	}

	app, err := fs.ReadFile(webAssets, "web/app.js")
	if err != nil {
		t.Fatalf("read web/app.js: %v", err)
	}
	for _, snippet := range []string{
		`get("packet_debug") === "1"`,
		`packetDebug: !!state.packetDebugEnabled,`,
		`type: "reset_packet_debug"`,
		`type === "packet_debug"`,
		`type === "incomudon-slot-packet-debug-request"`,
	} {
		if !strings.Contains(string(app), snippet) {
			t.Fatalf("packet debug client path is missing %q", snippet)
		}
	}

	multi, err := fs.ReadFile(webAssets, "web/multi.js")
	if err != nil {
		t.Fatalf("read web/multi.js: %v", err)
	}
	for _, snippet := range []string{
		`url.searchParams.set("packet_debug", "1")`,
		`incomudon-slot-packet-debug`,
		`incomudon-slot-packet-debug-request`,
		`multi-slot-packet-debug`,
	} {
		if !strings.Contains(string(multi), snippet) {
			t.Fatalf("packet debug multi-slot path is missing %q", snippet)
		}
	}
}

package main

import "testing"

func TestBuildSessionConfigDefaultsToSelfMute(t *testing.T) {
	base := clientCommand{
		RelayHost: "127.0.0.1",
		RelayPort: 50000,
		ChannelID: 1,
	}

	cfg, err := buildSessionConfig(base, "", "", false, "", 0)
	if err != nil {
		t.Fatalf("build default session config: %v", err)
	}
	if !cfg.SelfMute {
		t.Fatal("self mute must default to enabled")
	}

	disabled := false
	base.SelfMute = &disabled
	cfg, err = buildSessionConfig(base, "", "", false, "", 0)
	if err != nil {
		t.Fatalf("build session config with self mute disabled: %v", err)
	}
	if cfg.SelfMute {
		t.Fatal("explicit self mute=false must be preserved")
	}
}

func TestRelaySessionSelfMuteExcludesOnlyOwnSender(t *testing.T) {
	const selfSenderID uint32 = 42
	session := &relaySession{
		cfg: sessionConfig{
			SenderID: selfSenderID,
			SelfMute: true,
		},
		downlinkPCM:    make(map[uint32][]byte),
		downlinkQueues: make(map[uint32][][]byte),
	}
	frame := make([]byte, pcmBytesPerFrame)

	session.emitDownlinkAudio(selfSenderID, frame)
	if len(session.downlinkQueues) != 0 {
		t.Fatal("self sender frame was queued while self mute was enabled")
	}

	const remoteSenderID uint32 = 43
	session.emitDownlinkAudio(remoteSenderID, frame)
	if len(session.downlinkQueues[remoteSenderID]) != 1 {
		t.Fatal("remote sender frame was not queued")
	}

	session.SetSelfMuted(false)
	session.emitDownlinkAudio(selfSenderID, frame)
	if len(session.downlinkQueues[selfSenderID]) != 1 {
		t.Fatal("self sender frame was not queued after self mute was disabled")
	}

	session.SetSelfMuted(true)
	if _, exists := session.downlinkQueues[selfSenderID]; exists {
		t.Fatal("queued self sender frames were not discarded when self mute was enabled")
	}
}

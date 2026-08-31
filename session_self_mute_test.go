package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

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

func TestBuildSessionConfigPreservesPacketDebugFlag(t *testing.T) {
	enabled := true
	cfg, err := buildSessionConfig(clientCommand{
		RelayHost:   "127.0.0.1",
		RelayPort:   50000,
		ChannelID:   1,
		PacketDebug: &enabled,
	}, "", "", false, "", 0)
	if err != nil {
		t.Fatalf("build packet debug session config: %v", err)
	}
	if !cfg.PacketDebug {
		t.Fatal("packet debug must be enabled when explicitly requested")
	}
}

func TestPacketDebugSnapshotAndReset(t *testing.T) {
	session := &relaySession{
		startedAt: time.Now().Add(-time.Second),
		packetStats: packetDebugStats{
			RelayRxAudioPackets:  3,
			RelayRxAudioBySender: map[uint32]uint64{42: 3},
		},
		downlinkQueues: map[uint32][][]byte{
			10: {make([]byte, 1), make([]byte, 1)},
		},
	}

	snapshot := session.packetDebugSnapshot()
	if snapshot.UptimeMs == 0 {
		t.Fatal("packet debug snapshot must report session uptime")
	}
	if snapshot.DownlinkQueuedFrames != 2 || snapshot.DownlinkQueuedSenders != 1 {
		t.Fatalf("unexpected queued downlink stats: %#v", snapshot)
	}
	if snapshot.RelayRxAudioBySender[42] != 3 {
		t.Fatalf("sender packet counter was not copied: %#v", snapshot.RelayRxAudioBySender)
	}

	session.ResetPacketDebugStats()
	reset := session.packetDebugSnapshot()
	if reset.RelayRxAudioPackets != 0 || len(reset.RelayRxAudioBySender) != 0 {
		t.Fatalf("packet debug reset retained counters: %#v", reset)
	}
}

func TestWebsocketPacketDebugStatsOnlyCollectsWhenEnabled(t *testing.T) {
	stats := &websocketPacketDebugStats{}
	stats.noteQueued(serverBinaryAudio, 320)

	snapshot := packetDebugStats{}
	stats.apply(&snapshot, 3)
	if snapshot.WebSocketQueuedPCMFrames != 0 {
		t.Fatal("disabled WebSocket packet debug must not collect audio counters")
	}

	stats.setEnabled(true)
	stats.noteQueued(serverBinaryAudio, 320)
	stats.noteDropped(320)
	stats.noteWritten(wsMessage{msgType: websocket.BinaryMessage, payload: make([]byte, 321)})
	stats.apply(&snapshot, 3)
	if snapshot.WebSocketQueueDepth != 3 || snapshot.WebSocketQueuedPCMFrames != 1 || snapshot.WebSocketDroppedFrames != 1 || snapshot.WebSocketWrittenFrames != 1 {
		t.Fatalf("unexpected WebSocket packet debug stats: %#v", snapshot)
	}

	stats.reset()
	stats.apply(&snapshot, 0)
	if snapshot.WebSocketQueuedPCMFrames != 0 || snapshot.WebSocketDroppedFrames != 0 || snapshot.WebSocketWrittenFrames != 0 {
		t.Fatalf("WebSocket packet debug reset retained counters: %#v", snapshot)
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

func TestRelayPingReplyUpdatesLatency(t *testing.T) {
	statuses := make(chan relayLatencyStatus, 1)
	now := time.Now()
	session := &relaySession{
		pingNonce:      0x0102030405060708,
		pingSentAt:     now.Add(-17 * time.Millisecond),
		pingPending:    true,
		pingRTTMs:      -1,
		pingJitterMs:   -1,
		downlinkQueues: make(map[uint32][][]byte),
		cb: sessionCallbacks{
			onLatency: func(status relayLatencyStatus) {
				statuses <- status
			},
		},
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, session.pingNonce)

	session.handlePingReply(parsedPacket{Payload: payload})

	select {
	case status := <-statuses:
		if !status.Available || status.Pending || status.Unresponsive {
			t.Fatalf("unexpected latency status: %#v", status)
		}
		if status.RTTMs < 0 || status.JitterMs < 0 {
			t.Fatalf("missing latency measurement: %#v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("latency callback was not emitted")
	}
	if session.pingPending {
		t.Fatal("matching PONG must clear the pending probe")
	}
}

func TestRelayPingIntervalUsesActiveTraffic(t *testing.T) {
	idle := &relaySession{downlinkQueues: make(map[uint32][][]byte)}
	if got := idle.relayPingIntervalLocked(); got != relayPingIdleInterval {
		t.Fatalf("idle interval = %v, want %v", got, relayPingIdleInterval)
	}

	active := &relaySession{pttPressed: true, downlinkQueues: make(map[uint32][][]byte)}
	if got := active.relayPingIntervalLocked(); got != relayPingActiveInterval {
		t.Fatalf("active interval = %v, want %v", got, relayPingActiveInterval)
	}
}

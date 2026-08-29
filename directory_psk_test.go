package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectoryReceiverAcceptsAndRejectsReplay(t *testing.T) {
	psk := []byte(strings.Repeat("k", directoryPSKBytes))
	now := time.Now()
	document := directoryDocument{
		Version:   directoryProtocolVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Channels:  []directoryChannel{{ChannelID: 101, Name: "Operations"}},
		Speakers:  []directorySpeaker{{ChannelID: 101, SenderID: 1001, Name: "Dispatch"}},
	}
	document.Revision = directoryDocumentRevision(document)
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	epoch := []byte("directory-epoch!")
	envelope := sealDirectoryEnvelopeForTest(t, psk, "pwa-1", epoch, 1, document.ExpiresAt, payload)
	packet, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &directoryReceiver{psk: psk, keyID: "pwa-1", replay: make(map[string]directoryReplayState)}
	got, err := receiver.openDocument(packet)
	if err != nil {
		t.Fatalf("openDocument() error = %v", err)
	}
	if got.Revision != document.Revision || got.Channels[0].Name != "Operations" || got.Speakers[0].Name != "Dispatch" {
		t.Fatalf("openDocument() = %#v, want %#v", got, document)
	}
	if _, err := receiver.openDocument(packet); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("openDocument() replay error = %v, want replay rejection", err)
	}
}

func TestDirectoryReceiverRejectsTamperedCiphertext(t *testing.T) {
	psk := []byte(strings.Repeat("p", directoryPSKBytes))
	now := time.Now()
	document := directoryDocument{
		Version:   directoryProtocolVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Channels:  []directoryChannel{{ChannelID: 101, Name: "Operations"}},
	}
	document.Revision = directoryDocumentRevision(document)
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sealDirectoryEnvelopeForTest(t, psk, "pwa-1", []byte("directory-epoch!"), 1, document.ExpiresAt, payload)
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0x01
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	packet, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &directoryReceiver{psk: psk, keyID: "pwa-1", replay: make(map[string]directoryReplayState)}
	if _, err := receiver.openDocument(packet); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("openDocument() tamper error = %v, want authentication failure", err)
	}
}

func TestDirectoryReceiverAcceptsParticipantsDocument(t *testing.T) {
	psk := []byte(strings.Repeat("q", directoryPSKBytes))
	now := time.Now()
	document := directoryParticipantsDocument{
		Version:   directoryProtocolVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Participants: []directoryParticipant{
			{ChannelID: 101, SenderID: 1001, LastSeenAt: now.Unix(), Talking: true},
			{ChannelID: 101, SenderID: 1002, LastSeenAt: now.Unix()},
		},
	}
	document.Revision = directoryParticipantsDocumentRevision(document)
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sealDirectoryEnvelopeForType(t, psk, "pwa-1", []byte("directory-epoch!"), 2, document.ExpiresAt, payload, directoryEnvelopeParticipants)
	packet, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &directoryReceiver{psk: psk, keyID: "pwa-1", replay: make(map[string]directoryReplayState)}
	got, err := receiver.openParticipantsDocument(packet)
	if err != nil {
		t.Fatalf("openParticipantsDocument() error = %v", err)
	}
	if len(got.Participants) != 2 || !got.Participants[0].Talking {
		t.Fatalf("openParticipantsDocument() = %#v", got)
	}
}

func TestDirectoryReceiverUsesEphemeralPortForDirectStartup(t *testing.T) {
	psk := []byte(strings.Repeat("r", directoryPSKBytes))
	pskPath := filepath.Join(t.TempDir(), "directory.psk")
	if err := os.WriteFile(pskPath, []byte(base64.RawURLEncoding.EncodeToString(psk)), 0o600); err != nil {
		t.Fatal(err)
	}
	receiver, err := newDirectoryReceiver(directoryReceiverConfig{
		Enabled: true,
		PSKFile: pskPath,
	})
	if err != nil {
		t.Fatalf("newDirectoryReceiver() error = %v", err)
	}
	defer receiver.Close()
	local, ok := receiver.conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port == 0 {
		t.Fatalf("direct directory listener = %#v, want allocated UDP port", receiver.conn.LocalAddr())
	}
}

func TestDirectoryReceiverSendsAuthenticatedRegistration(t *testing.T) {
	psk := []byte(strings.Repeat("s", directoryPSKBytes))
	pskPath := filepath.Join(t.TempDir(), "directory.psk")
	if err := os.WriteFile(pskPath, []byte(base64.RawURLEncoding.EncodeToString(psk)), 0o600); err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	receiver, err := newDirectoryReceiver(directoryReceiverConfig{
		Enabled:       true,
		ListenAddress: ":0",
		PSKFile:       pskPath,
		RelayTarget:   relay.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("newDirectoryReceiver() error = %v", err)
	}
	defer receiver.Close()
	if err := receiver.sendRegistration(directoryEnvelopeRegister); err != nil {
		t.Fatalf("sendRegistration() error = %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, directoryMaxDatagramBytes)
	n, _, err := relay.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := receiver.openPayload(buffer[:n], directoryEnvelopeRegister, time.Now())
	if err != nil {
		t.Fatalf("openPayload() error = %v", err)
	}
	var registration directoryRegistration
	if err := decodeDirectoryJSON(payload, &registration); err != nil {
		t.Fatal(err)
	}
	if registration.InstanceID != receiver.instanceID || registration.Version != directoryProtocolVersion {
		t.Fatalf("registration = %#v, want instance %q", registration, receiver.instanceID)
	}
}

func TestDirectoryReceiverRequestsParticipantsAtDynamicTarget(t *testing.T) {
	psk := []byte(strings.Repeat("t", directoryPSKBytes))
	pskPath := filepath.Join(t.TempDir(), "directory.psk")
	if err := os.WriteFile(pskPath, []byte(base64.RawURLEncoding.EncodeToString(psk)), 0o600); err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	receiver, err := newDirectoryReceiver(directoryReceiverConfig{
		Enabled:       true,
		ListenAddress: ":0",
		PSKFile:       pskPath,
	})
	if err != nil {
		t.Fatalf("newDirectoryReceiver() error = %v", err)
	}
	defer receiver.Close()
	relayAddress := relay.LocalAddr().(*net.UDPAddr)
	if err := receiver.RequestParticipantsTo(relayAddress.IP.String(), relayAddress.Port); err != nil {
		t.Fatalf("RequestParticipantsTo() error = %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, directoryMaxDatagramBytes)
	n, _, err := relay.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := receiver.openPayload(buffer[:n], directoryEnvelopeRequest, time.Now())
	if err != nil {
		t.Fatalf("openPayload() error = %v", err)
	}
	var request directoryRequest
	if err := decodeDirectoryJSON(payload, &request); err != nil {
		t.Fatal(err)
	}
	if request.Version != directoryProtocolVersion || request.ExpiresAt <= request.IssuedAt {
		t.Fatalf("directory request = %#v", request)
	}
	if receiver.relayTarget != nil {
		t.Fatalf("dynamic participant pull unexpectedly set relay target = %s", receiver.relayTarget)
	}
}

func sealDirectoryEnvelopeForTest(t *testing.T, psk []byte, keyID string, epoch []byte, sequence uint64, expiresAt int64, payload []byte) directoryEnvelope {
	return sealDirectoryEnvelopeForType(t, psk, keyID, epoch, sequence, expiresAt, payload, directoryEnvelopeSnapshot)
}

func sealDirectoryEnvelopeForType(t *testing.T, psk []byte, keyID string, epoch []byte, sequence uint64, expiresAt int64, payload []byte, envelopeType string) directoryEnvelope {
	t.Helper()
	envelope := directoryEnvelope{
		Version:   directoryProtocolVersion,
		Type:      envelopeType,
		KeyID:     keyID,
		Epoch:     base64.RawURLEncoding.EncodeToString(epoch),
		Sequence:  sequence,
		ExpiresAt: expiresAt,
	}
	block, err := aes.NewCipher(deriveDirectoryKey(psk, epoch))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := directoryEnvelopeAAD(envelope, epoch)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(aead.Seal(nil, directoryNonce(sequence), payload, aad))
	return envelope
}

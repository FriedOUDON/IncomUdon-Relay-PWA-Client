package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
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

func sealDirectoryEnvelopeForTest(t *testing.T, psk []byte, keyID string, epoch []byte, sequence uint64, expiresAt int64, payload []byte) directoryEnvelope {
	t.Helper()
	envelope := directoryEnvelope{
		Version:   directoryProtocolVersion,
		Type:      directoryEnvelopeSnapshot,
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

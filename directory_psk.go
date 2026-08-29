package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const (
	directoryProtocolVersion         = 1
	directoryEnvelopeSnapshot        = "snapshot"
	directoryEnvelopeParticipants    = "participants"
	directoryEnvelopeRequest         = "request"
	directoryEnvelopeRegister        = "register"
	directoryEnvelopeHeartbeat       = "heartbeat"
	directoryPSKBytes                = 32
	directoryEpochBytes              = 16
	directoryMaxDatagramBytes        = 2048
	directoryMaxChannels             = 256
	directoryMaxSpeakers             = 4096
	directoryMaxParticipants         = 128
	directoryMaxNameRunes            = 128
	directoryMaxKeyIDBytes           = 64
	directoryMaxValidity             = 5 * time.Minute
	directoryDefaultKeyID            = "pwa-1"
	directoryRequestTTL              = 30 * time.Second
	directoryDefaultRegisterInterval = 15 * time.Second
	directoryKeyDerivationLabel      = "IncomUdon directory PSK v1 relay-to-pwa"
)

type directoryChannel struct {
	ChannelID uint32 `json:"channelId"`
	Name      string `json:"name"`
}

type directorySpeaker struct {
	ChannelID uint32 `json:"channelId"`
	SenderID  uint32 `json:"senderId"`
	Name      string `json:"name"`
}

type directoryDocument struct {
	Version   int                `json:"version"`
	Revision  string             `json:"revision"`
	IssuedAt  int64              `json:"issuedAt"`
	ExpiresAt int64              `json:"expiresAt"`
	Channels  []directoryChannel `json:"channels"`
	Speakers  []directorySpeaker `json:"speakers"`
}

// directoryParticipant contains only public relay presence metadata. It is
// intentionally independent from PWA/browser state so native clients can use
// the same directory envelope in a later implementation.
type directoryParticipant struct {
	ChannelID  uint32 `json:"channelId"`
	SenderID   uint32 `json:"senderId"`
	LastSeenAt int64  `json:"lastSeenAt"`
	Talking    bool   `json:"talking"`
}

type directoryParticipantsDocument struct {
	Version      int                    `json:"version"`
	Revision     string                 `json:"revision"`
	IssuedAt     int64                  `json:"issuedAt"`
	ExpiresAt    int64                  `json:"expiresAt"`
	Participants []directoryParticipant `json:"participants"`
}

type directoryRequest struct {
	Version   int   `json:"version"`
	IssuedAt  int64 `json:"issuedAt"`
	ExpiresAt int64 `json:"expiresAt"`
}

// directoryRegistration is address-free so the Relay can use the observed UDP
// source endpoint. Native clients can use this same versioned payload.
type directoryRegistration struct {
	Version    int    `json:"version"`
	InstanceID string `json:"instanceId"`
	IssuedAt   int64  `json:"issuedAt"`
	ExpiresAt  int64  `json:"expiresAt"`
}

type directoryEnvelope struct {
	Version    int    `json:"v"`
	Type       string `json:"type"`
	KeyID      string `json:"keyId"`
	Epoch      string `json:"epoch"`
	Sequence   uint64 `json:"sequence"`
	ExpiresAt  int64  `json:"expiresAt"`
	Ciphertext string `json:"ciphertext"`
}

type directoryReceiverConfig struct {
	Enabled          bool
	ListenAddress    string
	PSKFile          string
	KeyID            string
	AllowCIDRs       string
	RelayTarget      string
	RegisterInterval time.Duration
}

type directoryReplayState struct {
	Sequence  uint64
	ExpiresAt int64
}

type directoryReceiver struct {
	conn             *net.UDPConn
	psk              []byte
	keyID            string
	allowed          []*net.IPNet
	relayTarget      *net.UDPAddr
	controlEpoch     []byte
	instanceID       string
	registerInterval time.Duration
	controlMu        sync.Mutex
	controlSequence  uint64
	replayMu         sync.Mutex
	replay           map[string]directoryReplayState
	done             chan struct{}
	closeOnce        sync.Once
}

type directoryStore struct {
	mu           sync.RWMutex
	document     *directoryDocument
	participants *directoryParticipantsDocument
}

type directoryHub struct {
	mu          sync.Mutex
	subscribers map[chan<- wsMessage]struct{}
}

func newDirectoryReceiver(config directoryReceiverConfig) (*directoryReceiver, error) {
	config.ListenAddress = strings.TrimSpace(config.ListenAddress)
	config.PSKFile = strings.TrimSpace(config.PSKFile)
	config.KeyID = strings.TrimSpace(config.KeyID)
	config.RelayTarget = strings.TrimSpace(config.RelayTarget)
	if config.KeyID == "" {
		config.KeyID = directoryDefaultKeyID
	}
	if !config.Enabled {
		return nil, nil
	}
	if config.PSKFile == "" {
		return nil, fmt.Errorf("directory receiving requires a PSK file")
	}
	if config.ListenAddress == "" {
		config.ListenAddress = ":0"
	}
	if err := validateDirectoryKeyID(config.KeyID); err != nil {
		return nil, err
	}
	psk, err := loadDirectoryPSK(config.PSKFile)
	if err != nil {
		return nil, err
	}
	allowed, err := parseDirectoryAllowCIDRs(config.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve directory UDP listener: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen for directory UDP: %w", err)
	}
	var relayTarget *net.UDPAddr
	if config.RelayTarget != "" {
		relayTarget, err = net.ResolveUDPAddr("udp", config.RelayTarget)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("resolve relay directory UDP target: %w", err)
		}
	}
	controlEpoch := make([]byte, directoryEpochBytes)
	if _, err := rand.Read(controlEpoch); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate directory control epoch: %w", err)
	}
	instanceBytes := make([]byte, directoryEpochBytes)
	if _, err := rand.Read(instanceBytes); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate directory client instance ID: %w", err)
	}
	if config.RegisterInterval <= 0 {
		config.RegisterInterval = directoryDefaultRegisterInterval
	}
	if config.RegisterInterval < time.Second || config.RegisterInterval >= directoryMaxValidity {
		_ = conn.Close()
		return nil, fmt.Errorf("directory registration interval must be between 1s and %s", directoryMaxValidity)
	}
	return &directoryReceiver{
		conn:             conn,
		psk:              psk,
		keyID:            config.KeyID,
		allowed:          allowed,
		relayTarget:      relayTarget,
		controlEpoch:     controlEpoch,
		instanceID:       base64.RawURLEncoding.EncodeToString(instanceBytes),
		registerInterval: config.RegisterInterval,
		replay:           make(map[string]directoryReplayState),
		done:             make(chan struct{}),
	}, nil
}

func (r *directoryReceiver) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.done != nil {
			close(r.done)
		}
	})
	if r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

func (r *directoryReceiver) Run(onDocument func(*directoryDocument), onParticipants func(*directoryParticipantsDocument)) {
	if r == nil || r.conn == nil {
		return
	}
	defer r.closeOnce.Do(func() {
		if r.done != nil {
			close(r.done)
		}
	})
	if r.relayTarget != nil {
		go r.registrationLoop()
	}
	buffer := make([]byte, directoryMaxDatagramBytes+1)
	for {
		n, source, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("directory UDP read error: %v", err)
				continue
			}
			return
		}
		if n > directoryMaxDatagramBytes {
			log.Printf("directory UDP packet rejected from %s: too large", source)
			continue
		}
		if !r.sourceAllowed(source) {
			log.Printf("directory UDP packet rejected from %s: source not allowed", source)
			continue
		}
		envelopeType, err := r.envelopeType(buffer[:n])
		if err != nil {
			log.Printf("directory UDP packet rejected from %s: %v", source, err)
			continue
		}
		switch envelopeType {
		case directoryEnvelopeSnapshot:
			document, err := r.openDocument(buffer[:n])
			if err != nil {
				log.Printf("directory UDP packet rejected from %s: %v", source, err)
				continue
			}
			if onDocument != nil {
				onDocument(document)
			}
			log.Printf("directory snapshot accepted: revision=%s channels=%d speakers=%d", document.Revision[:12], len(document.Channels), len(document.Speakers))
		case directoryEnvelopeParticipants:
			document, err := r.openParticipantsDocument(buffer[:n])
			if err != nil {
				log.Printf("directory UDP packet rejected from %s: %v", source, err)
				continue
			}
			if onParticipants != nil {
				onParticipants(document)
			}
			log.Printf("directory participants accepted: revision=%s participants=%d", document.Revision[:12], len(document.Participants))
		default:
			log.Printf("directory UDP packet rejected from %s: unsupported envelope", source)
		}
	}
}

func (r *directoryReceiver) openDocument(packet []byte) (*directoryDocument, error) {
	now := time.Now()
	envelope, plaintext, err := r.openPayload(packet, directoryEnvelopeSnapshot, now)
	if err != nil {
		return nil, err
	}
	var document directoryDocument
	if err := decodeDirectoryJSON(plaintext, &document); err != nil {
		return nil, fmt.Errorf("invalid document: %w", err)
	}
	if err := validateDirectoryDocument(document, envelope.ExpiresAt, now); err != nil {
		return nil, err
	}
	if !r.acceptSequence(envelope, now.Unix()) {
		return nil, fmt.Errorf("replayed snapshot")
	}
	return cloneDirectoryDocument(&document), nil
}

func (r *directoryReceiver) openParticipantsDocument(packet []byte) (*directoryParticipantsDocument, error) {
	now := time.Now()
	envelope, plaintext, err := r.openPayload(packet, directoryEnvelopeParticipants, now)
	if err != nil {
		return nil, err
	}
	var document directoryParticipantsDocument
	if err := decodeDirectoryJSON(plaintext, &document); err != nil {
		return nil, fmt.Errorf("invalid participants document: %w", err)
	}
	if err := validateDirectoryParticipantsDocument(document, envelope.ExpiresAt, now); err != nil {
		return nil, err
	}
	if !r.acceptSequence(envelope, now.Unix()) {
		return nil, fmt.Errorf("replayed participants snapshot")
	}
	return cloneDirectoryParticipantsDocument(&document), nil
}

func (r *directoryReceiver) envelopeType(packet []byte) (string, error) {
	var envelope directoryEnvelope
	if err := decodeDirectoryJSON(packet, &envelope); err != nil {
		return "", fmt.Errorf("invalid envelope: %w", err)
	}
	if envelope.Version != directoryProtocolVersion || envelope.KeyID != r.keyID || !isDirectoryEnvelopeType(envelope.Type) {
		return "", fmt.Errorf("unsupported envelope")
	}
	return envelope.Type, nil
}

func (r *directoryReceiver) openPayload(packet []byte, expectedType string, now time.Time) (directoryEnvelope, []byte, error) {
	var envelope directoryEnvelope
	if err := decodeDirectoryJSON(packet, &envelope); err != nil {
		return directoryEnvelope{}, nil, fmt.Errorf("invalid envelope: %w", err)
	}
	if envelope.Version != directoryProtocolVersion || envelope.Type != expectedType || envelope.KeyID != r.keyID || envelope.Sequence == 0 {
		return directoryEnvelope{}, nil, fmt.Errorf("unsupported envelope")
	}
	if envelope.ExpiresAt <= now.Unix() || envelope.ExpiresAt > now.Add(directoryMaxValidity).Unix() {
		return directoryEnvelope{}, nil, fmt.Errorf("expired or excessive envelope validity")
	}
	epoch, err := base64.RawURLEncoding.DecodeString(envelope.Epoch)
	if err != nil || len(epoch) != directoryEpochBytes {
		return directoryEnvelope{}, nil, fmt.Errorf("invalid envelope epoch")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < aes.BlockSize+16 {
		return directoryEnvelope{}, nil, fmt.Errorf("invalid envelope ciphertext")
	}
	block, err := aes.NewCipher(deriveDirectoryKey(r.psk, epoch))
	if err != nil {
		return directoryEnvelope{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return directoryEnvelope{}, nil, err
	}
	aad, err := directoryEnvelopeAAD(envelope, epoch)
	if err != nil {
		return directoryEnvelope{}, nil, err
	}
	plaintext, err := aead.Open(nil, directoryNonce(envelope.Sequence), ciphertext, aad)
	if err != nil {
		return directoryEnvelope{}, nil, fmt.Errorf("authentication failed")
	}
	return envelope, plaintext, nil
}

// RequestParticipants asks the relay directory port for fresh static and
// participant snapshots. It only sends an authenticated, short-lived request;
// the response is still validated by Run before being published to browsers.
func (r *directoryReceiver) RequestParticipants() error {
	if r == nil || r.conn == nil || r.relayTarget == nil {
		return fmt.Errorf("relay directory pull is not configured")
	}
	return r.requestParticipantsTo(r.relayTarget)
}

// RequestParticipantsTo sends a one-shot authenticated pull to a browser-
// supplied relay directory endpoint. It deliberately does not change the
// receiver's configured target or registration loop.
func (r *directoryReceiver) RequestParticipantsTo(host string, port int) error {
	if r == nil || r.conn == nil {
		return fmt.Errorf("relay directory pull is not configured")
	}
	target, err := resolveDirectoryRelayTarget(host, port)
	if err != nil {
		return err
	}
	return r.requestParticipantsTo(target)
}

func (r *directoryReceiver) requestParticipantsTo(target *net.UDPAddr) error {
	if r == nil || r.conn == nil || target == nil {
		return fmt.Errorf("relay directory pull is not configured")
	}
	now := time.Now()
	request := directoryRequest{
		Version:   directoryProtocolVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(directoryRequestTTL).Unix(),
	}
	return r.sendControlTo(target, directoryEnvelopeRequest, request, request.ExpiresAt)
}

func (r *directoryReceiver) registrationLoop() {
	if err := r.sendRegistration(directoryEnvelopeRegister); err != nil {
		log.Printf("directory client registration failed: %v", err)
	}
	ticker := time.NewTicker(r.registerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			if err := r.sendRegistration(directoryEnvelopeHeartbeat); err != nil {
				log.Printf("directory client heartbeat failed: %v", err)
			}
		}
	}
}

func (r *directoryReceiver) sendRegistration(envelopeType string) error {
	if r == nil || r.conn == nil || r.relayTarget == nil {
		return fmt.Errorf("relay directory registration is not configured")
	}
	if envelopeType != directoryEnvelopeRegister && envelopeType != directoryEnvelopeHeartbeat {
		return fmt.Errorf("invalid directory registration type")
	}
	now := time.Now()
	registration := directoryRegistration{
		Version:    directoryProtocolVersion,
		InstanceID: r.instanceID,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(directoryRequestTTL).Unix(),
	}
	return r.sendControl(envelopeType, registration, registration.ExpiresAt)
}

func (r *directoryReceiver) sendControl(envelopeType string, payloadValue any, expiresAt int64) error {
	if r == nil || r.conn == nil || r.relayTarget == nil {
		return fmt.Errorf("relay directory control target is not configured")
	}
	return r.sendControlTo(r.relayTarget, envelopeType, payloadValue, expiresAt)
}

func (r *directoryReceiver) sendControlTo(target *net.UDPAddr, envelopeType string, payloadValue any, expiresAt int64) error {
	if r == nil || r.conn == nil || target == nil {
		return fmt.Errorf("relay directory control target is not configured")
	}
	payload, err := json.Marshal(payloadValue)
	if err != nil {
		return err
	}
	r.controlMu.Lock()
	r.controlSequence++
	sequence := r.controlSequence
	envelope, err := sealDirectoryEnvelope(r.psk, r.keyID, r.controlEpoch, sequence, expiresAt, payload, envelopeType)
	r.controlMu.Unlock()
	if err != nil {
		return err
	}
	packet, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(packet) > directoryMaxDatagramBytes {
		return fmt.Errorf("directory %s exceeds maximum datagram size", envelopeType)
	}
	if _, err := r.conn.WriteToUDP(packet, target); err != nil {
		return fmt.Errorf("send directory %s: %w", envelopeType, err)
	}
	return nil
}

func resolveDirectoryRelayTarget(host string, port int) (*net.UDPAddr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("directory host is required")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("directory port must be between 1 and 65535")
	}
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("resolve relay directory UDP target: %w", err)
	}
	return target, nil
}

func (r *directoryReceiver) acceptSequence(envelope directoryEnvelope, now int64) bool {
	// Snapshot and participant documents share a publisher epoch but travel as
	// independent UDP datagrams. Track replay state per document type so normal
	// UDP reordering cannot discard a valid static snapshot behind a newer
	// participant snapshot.
	key := envelope.Type + ":" + envelope.KeyID + ":" + envelope.Epoch
	r.replayMu.Lock()
	defer r.replayMu.Unlock()
	for replayKey, state := range r.replay {
		if state.ExpiresAt <= now {
			delete(r.replay, replayKey)
		}
	}
	if previous, ok := r.replay[key]; ok && envelope.Sequence <= previous.Sequence {
		return false
	}
	if len(r.replay) >= 8 {
		oldestKey := ""
		var oldestExpiry int64
		for replayKey, state := range r.replay {
			if oldestKey == "" || state.ExpiresAt < oldestExpiry {
				oldestKey = replayKey
				oldestExpiry = state.ExpiresAt
			}
		}
		delete(r.replay, oldestKey)
	}
	r.replay[key] = directoryReplayState{Sequence: envelope.Sequence, ExpiresAt: envelope.ExpiresAt}
	return true
}

func (r *directoryReceiver) sourceAllowed(source *net.UDPAddr) bool {
	if len(r.allowed) == 0 {
		return true
	}
	for _, cidr := range r.allowed {
		if cidr.Contains(source.IP) {
			return true
		}
	}
	return false
}

func parseDirectoryAllowCIDRs(raw string) ([]*net.IPNet, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	allowed := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid directory allowed CIDR %q: %w", part, err)
		}
		allowed = append(allowed, cidr)
	}
	return allowed, nil
}

func decodeDirectoryJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func validateDirectoryDocument(document directoryDocument, envelopeExpiresAt int64, now time.Time) error {
	if document.Version != directoryProtocolVersion || document.Revision == "" || len(document.Revision) != 64 || document.ExpiresAt != envelopeExpiresAt {
		return fmt.Errorf("invalid directory document metadata")
	}
	if document.Revision != directoryDocumentRevision(document) {
		return fmt.Errorf("directory document revision mismatch")
	}
	if document.IssuedAt > now.Add(30*time.Second).Unix() || document.IssuedAt < now.Add(-directoryMaxValidity).Unix() {
		return fmt.Errorf("invalid directory document issue time")
	}
	if document.ExpiresAt <= now.Unix() || document.ExpiresAt <= document.IssuedAt || document.ExpiresAt-document.IssuedAt > int64(directoryMaxValidity/time.Second) {
		return fmt.Errorf("invalid directory document expiry")
	}
	if len(document.Channels) == 0 || len(document.Channels) > directoryMaxChannels || len(document.Speakers) > directoryMaxSpeakers {
		return fmt.Errorf("directory document exceeds entry limits")
	}
	channels := make(map[uint32]struct{}, len(document.Channels))
	for index, channel := range document.Channels {
		if channel.ChannelID == 0 || !isDirectoryNameValid(channel.Name) {
			return fmt.Errorf("invalid channel entry")
		}
		if _, exists := channels[channel.ChannelID]; exists {
			return fmt.Errorf("duplicate channel entry")
		}
		if index > 0 && document.Channels[index-1].ChannelID >= channel.ChannelID {
			return fmt.Errorf("channels are not sorted")
		}
		channels[channel.ChannelID] = struct{}{}
	}
	speakers := make(map[[2]uint32]struct{}, len(document.Speakers))
	for index, speaker := range document.Speakers {
		if speaker.ChannelID == 0 || speaker.SenderID == 0 || !isDirectoryNameValid(speaker.Name) {
			return fmt.Errorf("invalid speaker entry")
		}
		if _, exists := channels[speaker.ChannelID]; !exists {
			return fmt.Errorf("speaker references unknown channel")
		}
		key := [2]uint32{speaker.ChannelID, speaker.SenderID}
		if _, exists := speakers[key]; exists {
			return fmt.Errorf("duplicate speaker entry")
		}
		if index > 0 {
			previous := document.Speakers[index-1]
			if previous.ChannelID > speaker.ChannelID || (previous.ChannelID == speaker.ChannelID && previous.SenderID >= speaker.SenderID) {
				return fmt.Errorf("speakers are not sorted")
			}
		}
		speakers[key] = struct{}{}
	}
	return nil
}

func validateDirectoryParticipantsDocument(document directoryParticipantsDocument, envelopeExpiresAt int64, now time.Time) error {
	if document.Version != directoryProtocolVersion || document.Revision == "" || len(document.Revision) != 64 || document.ExpiresAt != envelopeExpiresAt {
		return fmt.Errorf("invalid directory participants metadata")
	}
	if document.Revision != directoryParticipantsDocumentRevision(document) {
		return fmt.Errorf("directory participants revision mismatch")
	}
	if document.IssuedAt > now.Add(30*time.Second).Unix() || document.IssuedAt < now.Add(-directoryMaxValidity).Unix() {
		return fmt.Errorf("invalid directory participants issue time")
	}
	if document.ExpiresAt <= now.Unix() || document.ExpiresAt <= document.IssuedAt || document.ExpiresAt-document.IssuedAt > int64(directoryMaxValidity/time.Second) {
		return fmt.Errorf("invalid directory participants expiry")
	}
	if len(document.Participants) > directoryMaxParticipants {
		return fmt.Errorf("directory participants exceed entry limit")
	}
	seen := make(map[[2]uint32]struct{}, len(document.Participants))
	for index, participant := range document.Participants {
		if participant.ChannelID == 0 || participant.SenderID == 0 || participant.LastSeenAt <= 0 || participant.LastSeenAt > now.Add(30*time.Second).Unix() {
			return fmt.Errorf("invalid participant entry")
		}
		if participant.LastSeenAt < now.Add(-directoryMaxValidity).Unix() {
			return fmt.Errorf("stale participant entry")
		}
		key := [2]uint32{participant.ChannelID, participant.SenderID}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate participant entry")
		}
		if index > 0 {
			previous := document.Participants[index-1]
			if previous.ChannelID > participant.ChannelID || (previous.ChannelID == participant.ChannelID && previous.SenderID >= participant.SenderID) {
				return fmt.Errorf("participants are not sorted")
			}
		}
		seen[key] = struct{}{}
	}
	return nil
}

func isDirectoryNameValid(value string) bool {
	name := strings.TrimSpace(value)
	return name != "" && utf8.ValidString(name) && !strings.ContainsAny(name, "\r\n\x00") && utf8.RuneCountInString(name) <= directoryMaxNameRunes
}

func loadDirectoryPSK(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read directory PSK file: %w", err)
	}
	encoded := strings.TrimSpace(string(raw))
	psk, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		psk, err = base64.URLEncoding.DecodeString(encoded)
	}
	if err != nil || len(psk) != directoryPSKBytes {
		return nil, fmt.Errorf("directory PSK file must contain one base64url-encoded %d-byte key", directoryPSKBytes)
	}
	return psk, nil
}

func validateDirectoryKeyID(keyID string) error {
	if keyID == "" || len(keyID) > directoryMaxKeyIDBytes {
		return fmt.Errorf("directory key ID must be 1 to %d ASCII characters", directoryMaxKeyIDBytes)
	}
	for _, value := range []byte(keyID) {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.' {
			continue
		}
		return fmt.Errorf("directory key ID contains unsupported characters")
	}
	return nil
}

func validateDirectoryInstanceID(instanceID string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(instanceID)
	if err != nil || len(decoded) != directoryEpochBytes {
		return fmt.Errorf("invalid directory client instance ID")
	}
	return nil
}

func deriveDirectoryKey(psk, epoch []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(directoryKeyDerivationLabel))
	_, _ = mac.Write(epoch)
	return mac.Sum(nil)
}

func directoryNonce(sequence uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], []byte{'I', 'D', 'P', '1'})
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func directoryEnvelopeAAD(envelope directoryEnvelope, epoch []byte) ([]byte, error) {
	if len(epoch) != directoryEpochBytes {
		return nil, fmt.Errorf("invalid directory epoch")
	}
	if err := validateDirectoryKeyID(envelope.KeyID); err != nil {
		return nil, err
	}
	if !isDirectoryEnvelopeType(envelope.Type) {
		return nil, fmt.Errorf("invalid directory envelope type")
	}
	buffer := make([]byte, 0, 64+len(envelope.KeyID)+len(envelope.Type))
	buffer = append(buffer, []byte("IncomUdon Directory Envelope AAD v1\x00")...)
	buffer = append(buffer, byte(envelope.Version))
	buffer = append(buffer, byte(len(envelope.Type)))
	buffer = append(buffer, envelope.Type...)
	buffer = append(buffer, byte(len(envelope.KeyID)))
	buffer = append(buffer, envelope.KeyID...)
	buffer = append(buffer, epoch...)
	sequence := make([]byte, 8)
	binary.BigEndian.PutUint64(sequence, envelope.Sequence)
	buffer = append(buffer, sequence...)
	expiresAt := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAt, uint64(envelope.ExpiresAt))
	buffer = append(buffer, expiresAt...)
	return buffer, nil
}

func isDirectoryEnvelopeType(value string) bool {
	switch value {
	case directoryEnvelopeSnapshot, directoryEnvelopeParticipants, directoryEnvelopeRequest, directoryEnvelopeRegister, directoryEnvelopeHeartbeat:
		return true
	default:
		return false
	}
}

func sealDirectoryEnvelope(psk []byte, keyID string, epoch []byte, sequence uint64, expiresAt int64, payload []byte, envelopeType string) (directoryEnvelope, error) {
	if len(epoch) != directoryEpochBytes || sequence == 0 || !isDirectoryEnvelopeType(envelopeType) {
		return directoryEnvelope{}, fmt.Errorf("invalid directory envelope")
	}
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
		return directoryEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return directoryEnvelope{}, err
	}
	aad, err := directoryEnvelopeAAD(envelope, epoch)
	if err != nil {
		return directoryEnvelope{}, err
	}
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(aead.Seal(nil, directoryNonce(sequence), payload, aad))
	return envelope, nil
}

func cloneDirectoryDocument(document *directoryDocument) *directoryDocument {
	if document == nil {
		return nil
	}
	clone := *document
	clone.Channels = append([]directoryChannel(nil), document.Channels...)
	clone.Speakers = append([]directorySpeaker(nil), document.Speakers...)
	return &clone
}

func cloneDirectoryParticipantsDocument(document *directoryParticipantsDocument) *directoryParticipantsDocument {
	if document == nil {
		return nil
	}
	clone := *document
	clone.Participants = append([]directoryParticipant(nil), document.Participants...)
	return &clone
}

func (s *directoryStore) Set(document *directoryDocument) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.document = cloneDirectoryDocument(document)
	s.mu.Unlock()
}

func (s *directoryStore) Current() *directoryDocument {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	document := cloneDirectoryDocument(s.document)
	s.mu.RUnlock()
	if document != nil && document.ExpiresAt <= time.Now().Unix() {
		return nil
	}
	return document
}

func (s *directoryStore) SetParticipants(document *directoryParticipantsDocument) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.participants = cloneDirectoryParticipantsDocument(document)
	s.mu.Unlock()
}

func (s *directoryStore) CurrentParticipants() *directoryParticipantsDocument {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	document := cloneDirectoryParticipantsDocument(s.participants)
	s.mu.RUnlock()
	if document != nil && document.ExpiresAt <= time.Now().Unix() {
		return nil
	}
	return document
}

func newDirectoryHub() *directoryHub {
	return &directoryHub{subscribers: make(map[chan<- wsMessage]struct{})}
}

func (h *directoryHub) Subscribe(ch chan<- wsMessage) func() {
	if h == nil || ch == nil {
		return func() {}
	}
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
	}
}

func (h *directoryHub) Publish(document *directoryDocument) {
	if h == nil || document == nil {
		return
	}
	payload, err := json.Marshal(serverEvent{Type: "directory", Directory: cloneDirectoryDocument(document)})
	if err != nil {
		return
	}
	message := wsMessage{msgType: websocket.TextMessage, payload: payload}
	h.mu.Lock()
	defer h.mu.Unlock()
	for subscriber := range h.subscribers {
		select {
		case subscriber <- message:
		default:
		}
	}
}

func (h *directoryHub) PublishParticipants(document *directoryParticipantsDocument) {
	if h == nil || document == nil {
		return
	}
	payload, err := json.Marshal(serverEvent{Type: "directory_participants", DirectoryParticipants: cloneDirectoryParticipantsDocument(document)})
	if err != nil {
		return
	}
	message := wsMessage{msgType: websocket.TextMessage, payload: payload}
	h.mu.Lock()
	defer h.mu.Unlock()
	for subscriber := range h.subscribers {
		select {
		case subscriber <- message:
		default:
		}
	}
}

func directoryDocumentRevision(document directoryDocument) string {
	channels := append([]directoryChannel(nil), document.Channels...)
	speakers := append([]directorySpeaker(nil), document.Speakers...)
	sort.Slice(channels, func(i, j int) bool { return channels[i].ChannelID < channels[j].ChannelID })
	sort.Slice(speakers, func(i, j int) bool {
		if speakers[i].ChannelID != speakers[j].ChannelID {
			return speakers[i].ChannelID < speakers[j].ChannelID
		}
		return speakers[i].SenderID < speakers[j].SenderID
	})
	payload, _ := json.Marshal(struct {
		Channels []directoryChannel `json:"channels"`
		Speakers []directorySpeaker `json:"speakers"`
	}{channels, speakers})
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func directoryParticipantsDocumentRevision(document directoryParticipantsDocument) string {
	participants := append([]directoryParticipant(nil), document.Participants...)
	sort.Slice(participants, func(i, j int) bool {
		if participants[i].ChannelID != participants[j].ChannelID {
			return participants[i].ChannelID < participants[j].ChannelID
		}
		return participants[i].SenderID < participants[j].SenderID
	})
	payload, _ := json.Marshal(struct {
		Participants []directoryParticipant `json:"participants"`
	}{participants})
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func parseDirectoryID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || parsed == 0 || parsed > math.MaxUint32 {
		return 0, fmt.Errorf("invalid ID")
	}
	return uint32(parsed), nil
}

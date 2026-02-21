package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type sessionConfig struct {
	RelayHost     string
	RelayPort     int
	ChannelID     uint32
	SenderID      uint32
	Password      string
	CryptoMode    cryptoMode
	CodecMode     int
	PCMOnly       bool
	Codec2LibPath string
	OpusLibPath   string
	UplinkCodec   string
	DownlinkCodec string
}

const (
	browserCodecPCM  = "pcm"
	browserCodecOpus = "opus"

	uplinkCodecPCM  = browserCodecPCM
	uplinkCodecOpus = browserCodecOpus

	downlinkCodecPCM  = browserCodecPCM
	downlinkCodecOpus = browserCodecOpus
)

type sessionCallbacks struct {
	onEvent func(serverEvent)
	onPCM   func([]byte)
	onOpus  func([]byte)
}

type peerCodecConfig struct {
	Mode    int
	PCMOnly bool
}

type relaySession struct {
	cfg         sessionConfig
	conn        *net.UDPConn
	relayAddr   *net.UDPAddr
	crypto      *cryptoContext
	codec2      *codec2Engine
	opusDecoder *opusDecoderEngine
	opusEncoder *opusEncoderEngine

	cb sessionCallbacks

	sendMu sync.Mutex
	mu     sync.Mutex

	seq      uint16
	audioSeq uint16

	pttPressed    bool
	talkAllowed   bool
	currentTalker uint32

	joinRetriesLeft int
	serverLocked    bool
	pendingPCM      [][]byte
	txPCMBuffer     []byte
	downlinkPCM     []byte

	peerCodec          map[uint32]peerCodecConfig
	unsupportedFrames  map[string]struct{}
	startupWarnings    []string
	uplinkOpusWarned   bool
	downlinkOpusWarned bool

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newRelaySession(cfg sessionConfig, cb sessionCallbacks) (*relaySession, error) {
	relayAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", cfg.RelayHost, cfg.RelayPort))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve relay address: %w", err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to open udp socket: %w", err)
	}

	cryptoCtx, err := newCryptoContext(cfg.CryptoMode, cfg.Password, cfg.ChannelID)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to init crypto: %w", err)
	}

	s := &relaySession{
		cfg:               cfg,
		conn:              conn,
		relayAddr:         relayAddr,
		crypto:            cryptoCtx,
		cb:                cb,
		joinRetriesLeft:   5,
		peerCodec:         make(map[uint32]peerCodecConfig),
		unsupportedFrames: make(map[string]struct{}),
		done:              make(chan struct{}),
	}

	codec2Path := strings.TrimSpace(cfg.Codec2LibPath)
	if codec2Path != "" || !s.cfg.PCMOnly {
		engine, loadErr := newCodec2Engine(codec2Path)
		if loadErr != nil {
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Codec2 disabled: %v", loadErr))
			if !s.cfg.PCMOnly {
				s.cfg.PCMOnly = true
				s.startupWarnings = append(s.startupWarnings,
					"PCM only was forced because codec2 encoder is unavailable")
			}
		} else {
			s.codec2 = engine
		}
	}

	s.cfg.UplinkCodec = normalizeUplinkCodec(s.cfg.UplinkCodec)
	s.cfg.DownlinkCodec = normalizeDownlinkCodec(s.cfg.DownlinkCodec)

	if s.cfg.UplinkCodec == uplinkCodecOpus {
		opusPath := strings.TrimSpace(s.cfg.OpusLibPath)
		engine, loadErr := newOpusDecoderEngine(opusPath, 8000, 1)
		if loadErr != nil {
			s.cfg.UplinkCodec = uplinkCodecPCM
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Opus uplink disabled: %v", loadErr))
		} else {
			s.opusDecoder = engine
		}
	}
	if s.cfg.DownlinkCodec == downlinkCodecOpus {
		opusPath := strings.TrimSpace(s.cfg.OpusLibPath)
		engine, loadErr := newOpusEncoderEngine(opusPath, 8000, 1)
		if loadErr != nil {
			s.cfg.DownlinkCodec = downlinkCodecPCM
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Opus downlink disabled: %v", loadErr))
		} else {
			s.opusEncoder = engine
		}
	}

	return s, nil
}

func (s *relaySession) Start() {
	s.emitEvent(serverEvent{
		Type:      "status",
		Level:     "info",
		Message:   fmt.Sprintf("UDP socket opened on %s", s.conn.LocalAddr()),
		ChannelID: s.cfg.ChannelID,
		SenderID:  s.cfg.SenderID,
	})

	if s.codec2 != nil {
		message := "Codec2 dynamic library loaded"
		if path := strings.TrimSpace(s.codec2.LibraryPath()); path != "" {
			message = fmt.Sprintf("Codec2 dynamic library loaded: %s", path)
		}
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: message,
		})
	}
	if s.opusDecoder != nil {
		message := "Opus decoder library loaded"
		if path := strings.TrimSpace(s.opusDecoder.LibraryPath()); path != "" {
			message = fmt.Sprintf("Opus decoder library loaded: %s", path)
		}
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: message,
		})
	}
	if s.opusEncoder != nil {
		message := "Opus encoder library loaded"
		if path := strings.TrimSpace(s.opusEncoder.LibraryPath()); path != "" {
			message = fmt.Sprintf("Opus encoder library loaded: %s", path)
		}
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: message,
		})
	}
	for _, warning := range s.startupWarnings {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "warn",
			Message: warning,
		})
	}

	if err := s.sendJoin(); err != nil {
		s.emitError("failed to send join: %v", err)
	}
	if s.cfg.CryptoMode == cryptoLegacyXor {
		if err := s.sendLegacyHandshake(); err != nil {
			s.emitError("failed to send legacy handshake: %v", err)
		}
	}
	if err := s.sendCodecConfig(); err != nil {
		s.emitError("failed to send codec config: %v", err)
	}
	if err := s.sendKeepalive(); err != nil {
		s.emitError("failed to send keepalive: %v", err)
	}

	s.wg.Add(4)
	go s.readLoop()
	go s.keepaliveLoop()
	go s.joinRetryLoop()
	go s.codecLoop()
}

func (s *relaySession) Close() {
	s.closeOnce.Do(func() {
		_ = s.sendLeave()
		close(s.done)
		_ = s.conn.Close()
	})
	s.wg.Wait()

	s.mu.Lock()
	codec := s.codec2
	s.codec2 = nil
	opusDecoder := s.opusDecoder
	s.opusDecoder = nil
	opusEncoder := s.opusEncoder
	s.opusEncoder = nil
	s.pendingPCM = nil
	s.txPCMBuffer = nil
	s.downlinkPCM = nil
	s.mu.Unlock()
	if codec != nil {
		codec.Close()
	}
	if opusDecoder != nil {
		opusDecoder.Close()
	}
	if opusEncoder != nil {
		opusEncoder.Close()
	}
}

func (s *relaySession) EffectiveConfig() sessionConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *relaySession) HandleBrowserBinary(payload []byte) {
	if len(payload) < 2 {
		return
	}

	msgType := payload[0]
	body := payload[1:]

	switch msgType {
	case clientBinaryAudio:
		s.SendPCM(body)
	case clientBinaryOpus:
		s.mu.Lock()
		codec := s.cfg.UplinkCodec
		decoder := s.opusDecoder
		warned := s.uplinkOpusWarned
		s.mu.Unlock()

		if codec != uplinkCodecOpus || decoder == nil {
			if !warned {
				s.mu.Lock()
				if !s.uplinkOpusWarned {
					s.uplinkOpusWarned = true
					s.mu.Unlock()
					s.emitEvent(serverEvent{
						Type:    "status",
						Level:   "warn",
						Message: "Opus uplink packet ignored because Opus uplink is disabled",
					})
				} else {
					s.mu.Unlock()
				}
			}
			return
		}

		pcm, err := decoder.Decode(body)
		if err != nil {
			s.emitEvent(serverEvent{
				Type:    "status",
				Level:   "warn",
				Message: fmt.Sprintf("Opus uplink decode failed: %v", err),
			})
			return
		}
		s.SendPCM(pcm)
	default:
		return
	}
}

func (s *relaySession) SetPTT(pressed bool) {
	s.mu.Lock()
	if s.pttPressed == pressed {
		s.mu.Unlock()
		return
	}
	s.pttPressed = pressed
	if pressed {
		s.txPCMBuffer = nil
		s.talkAllowed = false
	} else {
		s.pendingPCM = nil
		s.txPCMBuffer = nil
		s.talkAllowed = false
	}
	s.mu.Unlock()

	if pressed {
		if err := s.sendCodecConfig(); err != nil {
			s.emitError("failed to send codec config: %v", err)
		}
		if err := s.sendControlPacket(pktPttOn, nil); err != nil {
			s.emitError("failed to send PTT_ON: %v", err)
		}
	} else {
		if err := s.sendControlPacket(pktPttOff, nil); err != nil {
			s.emitError("failed to send PTT_OFF: %v", err)
		}
	}
}

func (s *relaySession) UpdateCodec(codecMode int, pcmOnly bool) {
	forcedPCM := false

	s.mu.Lock()
	if !pcmOnly && s.codec2 == nil {
		pcmOnly = true
		forcedPCM = true
	}
	s.cfg.CodecMode = normalizeCodecMode(codecMode)
	s.cfg.PCMOnly = pcmOnly
	s.pendingPCM = nil
	s.txPCMBuffer = nil
	s.mu.Unlock()

	if forcedPCM {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "warn",
			Message: "PCM only was forced because codec2 encoder is unavailable",
		})
	}

	if err := s.sendCodecConfig(); err != nil {
		s.emitError("failed to update codec config: %v", err)
	}
}

func (s *relaySession) SendPCM(frame []byte) {
	pcm := sanitizePCM(frame)
	if len(pcm) == 0 {
		return
	}

	s.mu.Lock()
	pttPressed := s.pttPressed
	talkAllowed := s.talkAllowed
	if !pttPressed {
		s.mu.Unlock()
		return
	}
	if !talkAllowed {
		copied := append([]byte(nil), pcm...)
		if len(s.pendingPCM) >= 24 {
			s.pendingPCM = s.pendingPCM[1:]
		}
		s.pendingPCM = append(s.pendingPCM, copied)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if err := s.pushOutboundPCM(pcm); err != nil {
		s.emitError("failed to send audio frame: %v", err)
	}
}

func (s *relaySession) pushOutboundPCM(pcm []byte) error {
	frames := s.collectOutboundPCMFrames(pcm)
	for _, frame := range frames {
		if err := s.sendAudioFrame(frame); err != nil {
			return err
		}
	}
	return nil
}

func (s *relaySession) collectOutboundPCMFrames(pcm []byte) [][]byte {
	s.mu.Lock()
	pcmOnly := s.cfg.PCMOnly
	codecMode := s.cfg.CodecMode
	codec := s.codec2
	s.mu.Unlock()

	targetBytes := pcmBytesPerFrame
	if !pcmOnly && codec != nil {
		if bytesPerFrame, err := codec.PCMBytesForMode(codecMode); err == nil && bytesPerFrame > 0 {
			targetBytes = bytesPerFrame
		}
	}
	if targetBytes < 2 {
		targetBytes = pcmBytesPerFrame
	}

	s.mu.Lock()
	if len(s.txPCMBuffer) > targetBytes*64 {
		s.txPCMBuffer = nil
	}
	s.txPCMBuffer = append(s.txPCMBuffer, pcm...)
	frames := make([][]byte, 0, len(s.txPCMBuffer)/targetBytes+1)
	for len(s.txPCMBuffer) >= targetBytes {
		frame := append([]byte(nil), s.txPCMBuffer[:targetBytes]...)
		frames = append(frames, frame)
		s.txPCMBuffer = s.txPCMBuffer[targetBytes:]
	}
	s.mu.Unlock()
	return frames
}

func (s *relaySession) readLoop() {
	defer s.wg.Done()

	buf := make([]byte, 4096)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				s.emitError("udp read error: %v", err)
				continue
			}
		}

		datagram := make([]byte, n)
		copy(datagram, buf[:n])
		s.handleDatagram(datagram, addr)
	}
}

func (s *relaySession) keepaliveLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.sendKeepalive(); err != nil {
				s.emitError("failed to send keepalive: %v", err)
			}
		}
	}
}

func (s *relaySession) joinRetryLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.serverLocked {
				s.mu.Unlock()
				return
			}
			if s.joinRetriesLeft <= 0 {
				s.mu.Unlock()
				s.emitEvent(serverEvent{
					Type:    "status",
					Level:   "warn",
					Message: "No response from relay server (join retry limit reached)",
				})
				return
			}
			s.joinRetriesLeft--
			s.mu.Unlock()

			if err := s.sendJoin(); err != nil {
				s.emitError("failed to retry join: %v", err)
			}
		}
	}
}

func (s *relaySession) codecLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			pttPressed := s.pttPressed
			s.mu.Unlock()
			if !pttPressed {
				continue
			}
			if err := s.sendCodecConfig(); err != nil {
				s.emitError("failed to broadcast codec config: %v", err)
			}
		}
	}
}

func (s *relaySession) handleDatagram(data []byte, from *net.UDPAddr) {
	pkt, ok := parsePacket(data)
	if !ok {
		return
	}
	if pkt.Header.Version != protocolVersion {
		return
	}
	if pkt.Header.ChannelID != s.cfg.ChannelID {
		return
	}
	if !s.acceptServerAddress(from) {
		return
	}

	switch pkt.Header.Type {
	case pktTalkGrant, pktTalkRelease, pktTalkDeny:
		s.handleTalkPacket(pkt)
	case pktCodecConfig:
		s.handleCodecConfig(pkt)
	case pktAudio:
		s.handleAudioPacket(pkt)
	case pktKeyExchange:
		s.handleHandshakePacket(pkt)
	}
}

func (s *relaySession) acceptServerAddress(from *net.UDPAddr) bool {
	s.mu.Lock()
	if s.serverLocked {
		if s.relayAddr == nil {
			s.relayAddr = from
			s.mu.Unlock()
			return true
		}
		ok := udpAddrEqual(s.relayAddr, from)
		s.mu.Unlock()
		return ok
	}

	s.serverLocked = true
	s.relayAddr = from
	s.joinRetriesLeft = 0
	channelID := s.cfg.ChannelID
	message := fmt.Sprintf("Relay endpoint locked to %s", from.String())
	s.mu.Unlock()

	s.emitEvent(serverEvent{
		Type:      "status",
		Level:     "info",
		Message:   message,
		ChannelID: channelID,
	})
	return true
}

func (s *relaySession) handleTalkPacket(pkt parsedPacket) {
	talker := readTalkerPayload(pkt.Payload, pkt.Header.SenderID)
	if pkt.Header.Type == pktTalkRelease {
		talker = 0
	}

	var flushFrames [][]byte
	s.mu.Lock()
	s.currentTalker = talker
	s.talkAllowed = talker != 0 && talker == s.cfg.SenderID
	if s.talkAllowed && len(s.pendingPCM) > 0 {
		flushFrames = append(flushFrames, s.pendingPCM...)
		s.pendingPCM = nil
	}
	talkAllowed := s.talkAllowed
	s.mu.Unlock()

	s.emitEvent(serverEvent{
		Type:        "talker",
		TalkerID:    talker,
		TalkAllowed: talkAllowed,
	})

	if pkt.Header.Type == pktTalkDeny {
		s.emitEvent(serverEvent{
			Type:     "status",
			Level:    "warn",
			Message:  fmt.Sprintf("PTT denied. Current talker=%d", talker),
			TalkerID: talker,
		})
	}

	for _, frame := range flushFrames {
		if err := s.pushOutboundPCM(frame); err != nil {
			s.emitError("failed to flush queued audio: %v", err)
			break
		}
	}
}

func (s *relaySession) handleCodecConfig(pkt parsedPacket) {
	if len(pkt.Payload) < 3 {
		return
	}
	pcmOnly := (pkt.Payload[0] & 0x01) != 0
	mode := normalizeCodecMode(int(binary.BigEndian.Uint16(pkt.Payload[1:3])))

	s.mu.Lock()
	s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{Mode: mode, PCMOnly: pcmOnly}
	s.mu.Unlock()

	s.emitEvent(serverEvent{
		Type:      "peer_codec",
		SenderID:  pkt.Header.SenderID,
		CodecMode: mode,
		PCMOnly:   pcmOnly,
	})
}

func (s *relaySession) handleHandshakePacket(pkt parsedPacket) {
	payload := bytes.TrimSpace(pkt.Payload)
	if bytes.Equal(payload, []byte("LEGACY")) {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: "Received LEGACY handshake packet",
		})
	}
}

func (s *relaySession) handleAudioPacket(pkt parsedPacket) {
	plaintext := pkt.Payload

	s.mu.Lock()
	mode := s.cfg.CryptoMode
	s.mu.Unlock()

	if mode != cryptoNoCrypto {
		if !pkt.HasSecurity {
			return
		}
		decoded, err := s.crypto.decrypt(pkt.Payload, pkt.Tag, pkt.Sec.Nonce, nil)
		if err != nil {
			return
		}
		plaintext = decoded
	}

	frame := extractAudioFrame(plaintext)
	if len(frame) == 0 {
		return
	}

	if len(frame) == pcmBytesPerFrame {
		s.emitDownlinkAudio(frame)
		return
	}

	s.mu.Lock()
	peerCfg, hasPeer := s.peerCodec[pkt.Header.SenderID]
	codec := s.codec2
	s.mu.Unlock()

	if codec == nil {
		s.emitUnsupportedFrame(pkt.Header.SenderID, len(frame),
			"codec2 is unavailable")
		return
	}

	if hasPeer && !peerCfg.PCMOnly {
		decoded, err := codec.Decode(peerCfg.Mode, frame)
		if err == nil {
			s.emitDownlinkAudio(decoded)
			return
		}
	}

	decoded, detectedMode, err := codec.DecodeBySize(frame)
	if err != nil {
		s.emitUnsupportedFrame(pkt.Header.SenderID, len(frame), err.Error())
		return
	}

	s.mu.Lock()
	s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{Mode: detectedMode, PCMOnly: false}
	s.mu.Unlock()

	s.emitDownlinkAudio(decoded)
}

func (s *relaySession) emitUnsupportedFrame(senderID uint32, size int, reason string) {
	key := fmt.Sprintf("%d:%d", senderID, size)

	s.mu.Lock()
	_, exists := s.unsupportedFrames[key]
	if exists {
		s.mu.Unlock()
		return
	}
	s.unsupportedFrames[key] = struct{}{}
	s.mu.Unlock()

	message := fmt.Sprintf(
		"Received unsupported audio frame from sender=%d (size=%d)",
		senderID,
		size,
	)
	if reason != "" {
		message += ": " + reason
	}

	s.emitEvent(serverEvent{
		Type:     "status",
		Level:    "warn",
		SenderID: senderID,
		Message:  message,
	})
}

func (s *relaySession) emitDownlinkAudio(frame []byte) {
	frames := s.collectDownlinkPCMFrames(frame)
	for _, pcm := range frames {
		s.mu.Lock()
		downlinkCodec := s.cfg.DownlinkCodec
		encoder := s.opusEncoder
		warned := s.downlinkOpusWarned
		s.mu.Unlock()

		if downlinkCodec == downlinkCodecOpus && encoder != nil && s.cb.onOpus != nil {
			packet, err := encoder.Encode(pcm)
			if err == nil {
				s.cb.onOpus(packet)
				continue
			}

			if !warned {
				s.mu.Lock()
				if !s.downlinkOpusWarned {
					s.downlinkOpusWarned = true
					s.mu.Unlock()
					s.emitEvent(serverEvent{
						Type:    "status",
						Level:   "warn",
						Message: fmt.Sprintf("Opus downlink encode failed; fallback to PCM: %v", err),
					})
				} else {
					s.mu.Unlock()
				}
			}
		}

		if s.cb.onPCM != nil {
			s.cb.onPCM(pcm)
		}
	}
}

func (s *relaySession) collectDownlinkPCMFrames(frame []byte) [][]byte {
	pcm := sanitizePCM(frame)
	if len(pcm) == 0 {
		return nil
	}

	s.mu.Lock()
	if len(s.downlinkPCM) > pcmBytesPerFrame*64 {
		s.downlinkPCM = nil
	}
	s.downlinkPCM = append(s.downlinkPCM, pcm...)
	frames := make([][]byte, 0, len(s.downlinkPCM)/pcmBytesPerFrame+1)
	for len(s.downlinkPCM) >= pcmBytesPerFrame {
		out := append([]byte(nil), s.downlinkPCM[:pcmBytesPerFrame]...)
		frames = append(frames, out)
		s.downlinkPCM = s.downlinkPCM[pcmBytesPerFrame:]
	}
	s.mu.Unlock()

	return frames
}

func (s *relaySession) sendJoin() error {
	return s.sendControlPacket(pktJoin, nil)
}

func (s *relaySession) sendLeave() error {
	return s.sendControlPacket(pktLeave, nil)
}

func (s *relaySession) sendKeepalive() error {
	return s.sendControlPacket(pktKeepalive, nil)
}

func (s *relaySession) sendLegacyHandshake() error {
	return s.sendControlPacket(pktKeyExchange, []byte("LEGACY"))
}

func (s *relaySession) sendCodecConfig() error {
	s.mu.Lock()
	pcmOnly := s.cfg.PCMOnly
	codecMode := normalizeCodecMode(s.cfg.CodecMode)
	s.cfg.CodecMode = codecMode
	s.mu.Unlock()

	payload := make([]byte, 3)
	if pcmOnly {
		payload[0] = 0x01
	}
	binary.BigEndian.PutUint16(payload[1:3], uint16(codecMode))
	return s.sendControlPacket(pktCodecConfig, payload)
}

func (s *relaySession) sendControlPacket(pktType uint8, payload []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	select {
	case <-s.done:
		return fmt.Errorf("session closed")
	default:
	}

	s.mu.Lock()
	seq := s.seq
	s.seq++
	channelID := s.cfg.ChannelID
	senderID := s.cfg.SenderID
	mode := s.cfg.CryptoMode
	addr := s.relayAddr
	s.mu.Unlock()

	if addr == nil {
		return fmt.Errorf("relay address is not set")
	}

	var packet []byte
	if mode == cryptoNoCrypto {
		packet = buildNoCryptoPacket(pktType, channelID, senderID, seq, payload)
	} else {
		packet = buildPlainSecurePacket(pktType, channelID, senderID, seq, payload)
	}

	_, err := s.conn.WriteToUDP(packet, addr)
	return err
}

func (s *relaySession) sendAudioFrame(frame []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	select {
	case <-s.done:
		return fmt.Errorf("session closed")
	default:
	}

	s.mu.Lock()
	seq := s.seq
	s.seq++
	audioSeq := s.audioSeq
	s.audioSeq++
	channelID := s.cfg.ChannelID
	senderID := s.cfg.SenderID
	mode := s.cfg.CryptoMode
	keyID := s.crypto.keyID
	addr := s.relayAddr
	pcmOnly := s.cfg.PCMOnly
	codecMode := s.cfg.CodecMode
	codec := s.codec2
	nonce := uint64(0)
	if mode != cryptoNoCrypto {
		nonce = s.crypto.nextNonce()
	}
	s.mu.Unlock()

	if addr == nil {
		return fmt.Errorf("relay address is not set")
	}

	audioPCM := frame
	if pcmOnly {
		audioPCM = normalizePCMFrame(audioPCM)
	}

	audioFrame := audioPCM
	if !pcmOnly {
		if codec == nil {
			return fmt.Errorf("codec2 encoder is unavailable")
		}
		encoded, err := codec.Encode(codecMode, audioPCM)
		if err != nil {
			return fmt.Errorf("codec2 encode failed: %w", err)
		}
		audioFrame = encoded
	}

	payload := make([]byte, 2+len(audioFrame))
	binary.BigEndian.PutUint16(payload[:2], audioSeq)
	copy(payload[2:], audioFrame)

	var packet []byte
	if mode == cryptoNoCrypto {
		packet = buildNoCryptoPacket(pktAudio, channelID, senderID, seq, payload)
	} else {
		ciphertext, tag, err := s.crypto.encrypt(payload, nonce, nil)
		if err != nil {
			return err
		}
		packet = buildEncryptedPacket(pktAudio, channelID, senderID, seq, nonce, keyID, ciphertext, tag)
	}

	_, err := s.conn.WriteToUDP(packet, addr)
	return err
}

func (s *relaySession) emitEvent(event serverEvent) {
	if s.cb.onEvent != nil {
		s.cb.onEvent(event)
	}
}

func (s *relaySession) emitError(format string, args ...any) {
	s.emitEvent(serverEvent{
		Type:    "status",
		Level:   "error",
		Message: fmt.Sprintf(format, args...),
	})
}

func sanitizePCM(frame []byte) []byte {
	if len(frame) < 2 {
		return nil
	}
	usable := len(frame) &^ 1
	if usable <= 0 {
		return nil
	}
	return append([]byte(nil), frame[:usable]...)
}

func normalizePCMFrame(frame []byte) []byte {
	if len(frame) == pcmBytesPerFrame {
		return append([]byte(nil), frame...)
	}
	out := make([]byte, pcmBytesPerFrame)
	copy(out, frame)
	return out
}

func extractAudioFrame(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) == pcmBytesPerFrame {
		return append([]byte(nil), payload...)
	}
	if len(payload) < 2 {
		return nil
	}
	frame := payload[2:]
	if len(frame) == 0 {
		return nil
	}
	return append([]byte(nil), frame...)
}

func normalizeCodecMode(mode int) int {
	options := []int{450, 700, 1600, 2400, 3200}
	best := options[0]
	bestDiff := absInt(mode - best)
	for _, candidate := range options[1:] {
		diff := absInt(mode - candidate)
		if diff < bestDiff {
			bestDiff = diff
			best = candidate
		}
	}
	return best
}

func normalizeUplinkCodec(value string) string {
	return normalizeBrowserCodec(value)
}

func normalizeDownlinkCodec(value string) string {
	return normalizeBrowserCodec(value)
}

func normalizeBrowserCodec(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case browserCodecOpus:
		return browserCodecOpus
	default:
		return browserCodecPCM
	}
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	return a.IP.Equal(b.IP)
}

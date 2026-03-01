package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	pathpkg "path"
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
	TxCodec       string
	PCMOnly       bool
	QosEnabled    bool
	FecEnabled    bool
	Codec2LibPath string
	OpusLibPath   string
	UplinkCodec   string
	DownlinkCodec string
}

const (
	browserCodecPCM  = "pcm"
	browserCodecOpus = "opus"

	txCodecPCM    = "pcm"
	txCodecCodec2 = "codec2"
	txCodecOpus   = "opus"

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
	CodecID uint8
}

type relaySession struct {
	cfg         sessionConfig
	conn        *net.UDPConn
	relayAddr   *net.UDPAddr
	crypto      *cryptoContext
	codec2      *codec2Engine
	opusDecoder *opusDecoderEngine
	opusEncoder *opusEncoderEngine
	fec         *fecEncoder

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
	pendingOpus     [][]byte
	txPCMBuffer     []byte
	downlinkPCM     []byte

	peerCodec          map[uint32]peerCodecConfig
	unsupportedFrames  map[string]struct{}
	startupWarnings    []string
	qosApplied         bool
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
		fec:               newFECEncoder(cfg.FecEnabled),
		cb:                cb,
		joinRetriesLeft:   5,
		peerCodec:         make(map[uint32]peerCodecConfig),
		unsupportedFrames: make(map[string]struct{}),
		done:              make(chan struct{}),
	}

	if err := applyUDPSocketQoS(conn, s.cfg.QosEnabled); err != nil {
		s.startupWarnings = append(s.startupWarnings,
			fmt.Sprintf("Network QoS request failed: %v", err))
	} else {
		s.qosApplied = true
	}

	s.cfg.UplinkCodec = normalizeUplinkCodec(s.cfg.UplinkCodec)
	s.cfg.DownlinkCodec = normalizeDownlinkCodec(s.cfg.DownlinkCodec)
	s.cfg.TxCodec = normalizeTxCodec(s.cfg.TxCodec)
	s.cfg.PCMOnly = s.cfg.TxCodec == txCodecPCM

	requiresCodec2Uplink := s.cfg.TxCodec == txCodecCodec2
	codec2Path := strings.TrimSpace(cfg.Codec2LibPath)
	if codec2Path == "" && !requiresCodec2Uplink {
		log.Printf(
			"codec2 load skipped (txCodec=%s channel=%d sender=%d): tx codec does not require codec2 and no codec2 library path was provided",
			s.cfg.TxCodec,
			s.cfg.ChannelID,
			s.cfg.SenderID,
		)
	} else {
		log.Printf(
			"codec2 load attempt (txCodec=%s channel=%d sender=%d requested=%q requiredByTx=%t)",
			s.cfg.TxCodec,
			s.cfg.ChannelID,
			s.cfg.SenderID,
			codec2Path,
			requiresCodec2Uplink,
		)
		codec2LibName := libraryDisplayName(codec2Path, "libcodec2.so")
		engine, loadErr := newCodec2Engine(codec2Path)
		if loadErr != nil {
			log.Printf(
				"codec2 load failed (requested=%q txCodec=%s channel=%d sender=%d): %v",
				codec2Path,
				s.cfg.TxCodec,
				s.cfg.ChannelID,
				s.cfg.SenderID,
				loadErr,
			)
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Codec2 library load failed (%s)", codec2LibName))
			if requiresCodec2Uplink {
				s.cfg.TxCodec = txCodecPCM
				s.cfg.PCMOnly = true
				s.startupWarnings = append(s.startupWarnings,
					"TX codec was forced to PCM because codec2 encoder is unavailable")
			}
		} else {
			s.codec2 = engine
			codec2LibName = libraryDisplayName(engine.LibraryPath(), codec2LibName)
			log.Printf(
				"codec2 load success (txCodec=%s channel=%d sender=%d resolved=%q abi=%d)",
				s.cfg.TxCodec,
				s.cfg.ChannelID,
				s.cfg.SenderID,
				engine.LibraryPath(),
				engine.ABIVersion(),
			)
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Codec2 library load succeeded (%s)", codec2LibName))
		}
	}

	loadDecoder := s.cfg.UplinkCodec == uplinkCodecOpus || s.cfg.DownlinkCodec == downlinkCodecOpus || s.cfg.TxCodec == txCodecOpus
	loadEncoder := s.cfg.DownlinkCodec == downlinkCodecOpus || s.cfg.TxCodec == txCodecOpus
	if loadDecoder {
		opusPath := strings.TrimSpace(s.cfg.OpusLibPath)
		opusLibName := libraryDisplayName(opusPath, "libopus.so")
		engine, loadErr := newOpusDecoderEngine(opusPath, 8000, 1)
		if loadErr != nil {
			log.Printf(
				"opus decoder load failed (requested=%q txCodec=%s uplink=%s downlink=%s channel=%d sender=%d): %v",
				opusPath,
				s.cfg.TxCodec,
				s.cfg.UplinkCodec,
				s.cfg.DownlinkCodec,
				s.cfg.ChannelID,
				s.cfg.SenderID,
				loadErr,
			)
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Opus decoder library load failed (%s)", opusLibName))
			if s.cfg.UplinkCodec == uplinkCodecOpus && s.cfg.TxCodec != txCodecOpus {
				s.cfg.UplinkCodec = uplinkCodecPCM
				s.startupWarnings = append(s.startupWarnings,
					"Browser uplink opus was disabled because Opus decoder is unavailable")
			}
		} else {
			s.opusDecoder = engine
			opusLibName = libraryDisplayName(engine.LibraryPath(), opusLibName)
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Opus decoder library load succeeded (%s)", opusLibName))
		}
	}
	if loadEncoder {
		opusPath := strings.TrimSpace(s.cfg.OpusLibPath)
		opusLibName := libraryDisplayName(opusPath, "libopus.so")
		engine, loadErr := newOpusEncoderEngine(opusPath, 8000, 1)
		if loadErr != nil {
			log.Printf(
				"opus encoder load failed (requested=%q txCodec=%s uplink=%s downlink=%s channel=%d sender=%d): %v",
				opusPath,
				s.cfg.TxCodec,
				s.cfg.UplinkCodec,
				s.cfg.DownlinkCodec,
				s.cfg.ChannelID,
				s.cfg.SenderID,
				loadErr,
			)
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Opus encoder library load failed (%s)", opusLibName))
			if s.cfg.TxCodec == txCodecOpus {
				s.cfg.TxCodec = txCodecPCM
				s.cfg.PCMOnly = true
				s.startupWarnings = append(s.startupWarnings,
					"TX codec was forced to PCM because Opus encoder is unavailable")
			}
			if s.cfg.DownlinkCodec == downlinkCodecOpus {
				s.cfg.DownlinkCodec = downlinkCodecPCM
				s.startupWarnings = append(s.startupWarnings,
					"Browser downlink opus was disabled because Opus encoder is unavailable")
			}
		} else {
			s.opusEncoder = engine
			opusLibName = libraryDisplayName(engine.LibraryPath(), opusLibName)
			s.startupWarnings = append(s.startupWarnings,
				fmt.Sprintf("Opus encoder library load succeeded (%s)", opusLibName))
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

	if s.cfg.QosEnabled {
		if s.qosApplied {
			s.emitEvent(serverEvent{
				Type:    "status",
				Level:   "info",
				Message: "Network QoS enabled (DSCP EF)",
			})
		}
	} else {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: "Network QoS disabled",
		})
	}
	if s.cfg.FecEnabled {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: "TX FEC enabled (RS 2-loss parity)",
		})
	} else {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: "TX FEC disabled",
		})
	}

	for _, warning := range s.startupWarnings {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   startupStatusLevel(warning),
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
	s.pendingOpus = nil
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
		transportCodec := s.activeUplinkTransportCodecLocked()
		codec := s.cfg.UplinkCodec
		decoder := s.opusDecoder
		warned := s.uplinkOpusWarned
		s.mu.Unlock()

		if transportCodec == codecTransportOpus {
			s.SendOpus(body)
			return
		}

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
		s.pendingOpus = nil
		s.talkAllowed = false
	} else {
		s.pendingPCM = nil
		s.pendingOpus = nil
		s.txPCMBuffer = nil
		s.talkAllowed = false
	}
	fec := s.fec
	s.mu.Unlock()
	if fec != nil {
		fec.Reset()
	}

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
	if pcmOnly {
		s.cfg.TxCodec = txCodecPCM
	} else if s.cfg.TxCodec == txCodecPCM {
		s.cfg.TxCodec = txCodecCodec2
	}

	requiresCodec2Uplink := s.cfg.TxCodec == txCodecCodec2
	if requiresCodec2Uplink && s.codec2 == nil {
		pcmOnly = true
		forcedPCM = true
		s.cfg.TxCodec = txCodecPCM
	}
	if s.cfg.TxCodec == txCodecOpus && s.opusEncoder == nil {
		pcmOnly = true
		forcedPCM = true
		s.cfg.TxCodec = txCodecPCM
	}
	s.cfg.CodecMode = normalizeCodecModeForTxCodec(codecMode, s.cfg.TxCodec)
	s.cfg.PCMOnly = pcmOnly
	s.pendingPCM = nil
	s.pendingOpus = nil
	s.txPCMBuffer = nil
	fec := s.fec
	s.mu.Unlock()
	if fec != nil {
		fec.Reset()
	}

	if forcedPCM {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "warn",
			Message: "TX codec was forced to PCM because selected encoder is unavailable",
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

func (s *relaySession) SendOpus(packet []byte) {
	if len(packet) == 0 {
		return
	}

	s.mu.Lock()
	pttPressed := s.pttPressed
	talkAllowed := s.talkAllowed
	transportCodec := s.activeUplinkTransportCodecLocked()
	if !pttPressed {
		s.mu.Unlock()
		return
	}
	if !talkAllowed {
		copied := append([]byte(nil), packet...)
		if len(s.pendingOpus) >= 24 {
			s.pendingOpus = s.pendingOpus[1:]
		}
		s.pendingOpus = append(s.pendingOpus, copied)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if transportCodec != codecTransportOpus {
		return
	}
	if err := s.sendAudioFrame(packet, codecTransportOpus); err != nil {
		s.emitError("failed to send opus frame: %v", err)
	}
}

func (s *relaySession) pushOutboundPCM(pcm []byte) error {
	frames := s.collectOutboundPCMFrames(pcm)
	for _, frame := range frames {
		if err := s.sendAudioFrame(frame, codecTransportPCM); err != nil {
			return err
		}
	}
	return nil
}

func (s *relaySession) collectOutboundPCMFrames(pcm []byte) [][]byte {
	s.mu.Lock()
	transportCodec := s.activeUplinkTransportCodecLocked()
	codecMode := s.cfg.CodecMode
	codec := s.codec2
	s.mu.Unlock()

	targetBytes := pcmBytesPerFrame
	if transportCodec == codecTransportCodec2 && codec != nil {
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
	case pktServerCfg:
		s.handleServerConfig(pkt)
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

	var flushPCM [][]byte
	var flushOpus [][]byte
	s.mu.Lock()
	s.currentTalker = talker
	s.talkAllowed = talker != 0 && talker == s.cfg.SenderID
	if s.talkAllowed && len(s.pendingPCM) > 0 {
		flushPCM = append(flushPCM, s.pendingPCM...)
		s.pendingPCM = nil
	}
	if s.talkAllowed && len(s.pendingOpus) > 0 {
		flushOpus = append(flushOpus, s.pendingOpus...)
		s.pendingOpus = nil
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

	for _, frame := range flushPCM {
		if err := s.pushOutboundPCM(frame); err != nil {
			s.emitError("failed to flush queued audio: %v", err)
			break
		}
	}
	for _, frame := range flushOpus {
		if err := s.sendAudioFrame(frame, codecTransportOpus); err != nil {
			s.emitError("failed to flush queued opus audio: %v", err)
			break
		}
	}
}

func (s *relaySession) handleCodecConfig(pkt parsedPacket) {
	if len(pkt.Payload) < 3 {
		return
	}
	pcmOnly := (pkt.Payload[0] & 0x01) != 0
	codecID := normalizeCodecTransportID(codecTransportCodec2, pcmOnly)
	mode := normalizeCodecModeForTransport(int(binary.BigEndian.Uint16(pkt.Payload[1:3])), codecID, pcmOnly)
	if len(pkt.Payload) >= 4 {
		codecID = normalizeCodecTransportID(pkt.Payload[1], pcmOnly)
		mode = normalizeCodecModeForTransport(int(binary.BigEndian.Uint16(pkt.Payload[2:4])), codecID, pcmOnly)
	}

	s.mu.Lock()
	s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{
		Mode:    mode,
		PCMOnly: pcmOnly,
		CodecID: codecID,
	}
	s.mu.Unlock()

	s.emitEvent(serverEvent{
		Type:      "peer_codec",
		SenderID:  pkt.Header.SenderID,
		CodecMode: mode,
		PCMOnly:   pcmOnly,
	})
}

func (s *relaySession) handleServerConfig(pkt parsedPacket) {
	if len(pkt.Payload) < 2 {
		return
	}
	timeoutSec := uint32(binary.BigEndian.Uint16(pkt.Payload[:2]))
	s.emitEvent(serverEvent{
		Type:           "server_config",
		TalkTimeoutSec: timeoutSec,
	})
	if timeoutSec == 0 {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "info",
			Message: "Server TX timeout is disabled",
		})
		return
	}
	s.emitEvent(serverEvent{
		Type:    "status",
		Level:   "info",
		Message: fmt.Sprintf("Server TX timeout: %ds", timeoutSec),
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

	s.mu.Lock()
	peerCfg, hasPeer := s.peerCodec[pkt.Header.SenderID]
	codec := s.codec2
	opusDecoder := s.opusDecoder
	downlinkCodec := s.cfg.DownlinkCodec
	s.mu.Unlock()

	if hasPeer {
		codecID := normalizeCodecTransportID(peerCfg.CodecID, peerCfg.PCMOnly)
		switch codecID {
		case codecTransportPCM:
			s.emitDownlinkAudio(frame)
			return
		case codecTransportOpus:
			if downlinkCodec == downlinkCodecOpus && s.cb.onOpus != nil {
				s.cb.onOpus(append([]byte(nil), frame...))
				return
			}
			if opusDecoder == nil {
				s.emitUnsupportedFrame(pkt.Header.SenderID, len(frame),
					"opus decoder is unavailable")
				return
			}
			decoded, err := opusDecoder.Decode(frame)
			if err != nil {
				s.emitUnsupportedFrame(pkt.Header.SenderID, len(frame), err.Error())
				return
			}
			s.emitDownlinkAudio(decoded)
			return
		default:
			if codec == nil {
				s.emitUnsupportedFrame(pkt.Header.SenderID, len(frame),
					"codec2 is unavailable")
				return
			}
			decoded, err := codec.Decode(peerCfg.Mode, frame)
			if err == nil {
				s.emitDownlinkAudio(decoded)
				return
			}
		}
	}

	if len(frame) == pcmBytesPerFrame {
		s.mu.Lock()
		s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{
			Mode:    normalizeCodecModeForTransport(s.cfg.CodecMode, codecTransportPCM, true),
			PCMOnly: true,
			CodecID: codecTransportPCM,
		}
		s.mu.Unlock()
		s.emitDownlinkAudio(frame)
		return
	}

	if codec != nil {
		decoded, detectedMode, err := codec.DecodeBySize(frame)
		if err == nil {
			s.mu.Lock()
			s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{
				Mode:    detectedMode,
				PCMOnly: false,
				CodecID: codecTransportCodec2,
			}
			s.mu.Unlock()
			s.emitDownlinkAudio(decoded)
			return
		}
	}

	if downlinkCodec == downlinkCodecOpus && s.cb.onOpus != nil {
		s.mu.Lock()
		s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{
			Mode:    normalizeCodecModeForTransport(s.cfg.CodecMode, codecTransportOpus, false),
			PCMOnly: false,
			CodecID: codecTransportOpus,
		}
		s.mu.Unlock()
		s.cb.onOpus(append([]byte(nil), frame...))
		return
	}

	if opusDecoder != nil {
		decoded, err := opusDecoder.Decode(frame)
		if err == nil {
			s.mu.Lock()
			s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{
				Mode:    normalizeCodecModeForTransport(s.cfg.CodecMode, codecTransportOpus, false),
				PCMOnly: false,
				CodecID: codecTransportOpus,
			}
			s.mu.Unlock()
			s.emitDownlinkAudio(decoded)
			return
		}
	}

	s.emitUnsupportedFrame(pkt.Header.SenderID, len(frame), "no compatible decoder")
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
	codecID := s.activeUplinkTransportCodecLocked()
	pcmOnly := codecID == codecTransportPCM
	codecMode := normalizeCodecModeForTransport(s.cfg.CodecMode, codecID, pcmOnly)
	s.cfg.CodecMode = codecMode
	s.mu.Unlock()

	payload := make([]byte, 4)
	if pcmOnly {
		payload[0] = 0x01
	}
	payload[1] = codecID
	binary.BigEndian.PutUint16(payload[2:4], uint16(codecMode))
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

func (s *relaySession) sendAudioFrame(frame []byte, sourceCodecID uint8) error {
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
	fecEnabled := s.cfg.FecEnabled
	fec := s.fec
	codecMode := s.cfg.CodecMode
	codec := s.codec2
	opusEncoder := s.opusEncoder
	transportCodec := s.activeUplinkTransportCodecLocked()
	nonce := uint64(0)
	if mode != cryptoNoCrypto {
		nonce = s.crypto.nextNonce()
	}
	s.mu.Unlock()

	if addr == nil {
		return fmt.Errorf("relay address is not set")
	}

	var audioFrame []byte
	if sourceCodecID == codecTransportOpus {
		if transportCodec != codecTransportOpus {
			return fmt.Errorf("opus frame rejected because uplink transport is not opus")
		}
		audioFrame = append([]byte(nil), frame...)
	} else {
		audioPCM := frame
		switch transportCodec {
		case codecTransportPCM:
			audioFrame = normalizePCMFrame(audioPCM)
		case codecTransportOpus:
			if opusEncoder == nil {
				return fmt.Errorf("opus encoder is unavailable")
			}
			encoded, err := opusEncoder.Encode(audioPCM)
			if err != nil {
				return fmt.Errorf("opus encode failed: %w", err)
			}
			audioFrame = encoded
		default:
			if codec == nil {
				return fmt.Errorf("codec2 encoder is unavailable")
			}
			encoded, err := codec.Encode(codecMode, audioPCM)
			if err != nil {
				return fmt.Errorf("codec2 encode failed: %w", err)
			}
			audioFrame = encoded
		}
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
	if err != nil {
		return err
	}

	if !fecEnabled || fec == nil {
		return nil
	}

	parityPackets := fec.AddFrame(audioSeq, audioFrame)
	for _, parity := range parityPackets {
		fecPayload := make([]byte, 4+len(parity.Data))
		binary.BigEndian.PutUint16(fecPayload[0:2], parity.BlockStart)
		fecPayload[2] = parity.BlockSize
		fecPayload[3] = parity.ParityIndex
		copy(fecPayload[4:], parity.Data)

		s.mu.Lock()
		fecSeq := s.seq
		s.seq++
		fecKeyID := s.crypto.keyID
		fecNonce := uint64(0)
		if mode != cryptoNoCrypto {
			fecNonce = s.crypto.nextNonce()
		}
		s.mu.Unlock()

		var fecPacket []byte
		if mode == cryptoNoCrypto {
			fecPacket = buildNoCryptoPacket(pktFec, channelID, senderID, fecSeq, fecPayload)
		} else {
			ciphertext, tag, encErr := s.crypto.encrypt(fecPayload, fecNonce, nil)
			if encErr != nil {
				return encErr
			}
			fecPacket = buildEncryptedPacket(pktFec, channelID, senderID, fecSeq, fecNonce, fecKeyID, ciphertext, tag)
		}

		if _, err := s.conn.WriteToUDP(fecPacket, addr); err != nil {
			return err
		}
	}

	return nil
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

var codec2ModeOptions = []int{450, 700, 1600, 2400, 3200}
var opusBitrateOptions = []int{6000, 8000, 12000, 16000, 20000, 64000, 96000, 128000}

func normalizeCodec2Mode(mode int) int {
	return nearestIntOption(codec2ModeOptions, mode)
}

// normalizeCodecMode is kept for codec2 helper compatibility.
func normalizeCodecMode(mode int) int {
	return normalizeCodec2Mode(mode)
}

func normalizeOpusBitrate(mode int) int {
	target := mode
	if target < opusBitrateOptions[0] {
		target = legacyCodec2ModeToOpusBitrate(mode)
	}
	return nearestIntOption(opusBitrateOptions, target)
}

func normalizeCodecModeForTxCodec(mode int, txCodec string) int {
	if normalizeTxCodec(txCodec) == txCodecOpus {
		return normalizeOpusBitrate(mode)
	}
	return normalizeCodec2Mode(mode)
}

func normalizeCodecModeForTransport(mode int, codecID uint8, pcmOnly bool) int {
	switch normalizeCodecTransportID(codecID, pcmOnly) {
	case codecTransportOpus:
		return normalizeOpusBitrate(mode)
	default:
		return normalizeCodec2Mode(mode)
	}
}

func legacyCodec2ModeToOpusBitrate(mode int) int {
	switch {
	case mode <= 450:
		return 6000
	case mode <= 700:
		return 8000
	case mode <= 1600:
		return 12000
	case mode <= 2400:
		return 16000
	default:
		return 20000
	}
}

func nearestIntOption(options []int, value int) int {
	if len(options) == 0 {
		return value
	}
	best := options[0]
	bestDiff := absInt(value - best)
	for _, candidate := range options[1:] {
		diff := absInt(value - candidate)
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

func normalizeTxCodec(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case txCodecCodec2:
		return txCodecCodec2
	case txCodecOpus:
		return txCodecOpus
	default:
		return txCodecPCM
	}
}

func normalizeBrowserCodec(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case browserCodecOpus:
		return browserCodecOpus
	default:
		return browserCodecPCM
	}
}

func (s *relaySession) activeUplinkTransportCodecLocked() uint8 {
	switch normalizeTxCodec(s.cfg.TxCodec) {
	case txCodecCodec2:
		return codecTransportCodec2
	case txCodecOpus:
		return codecTransportOpus
	default:
		return codecTransportPCM
	}
}

func normalizeCodecTransportID(codecID uint8, pcmOnly bool) uint8 {
	if pcmOnly {
		return codecTransportPCM
	}
	switch codecID {
	case codecTransportPCM, codecTransportCodec2, codecTransportOpus:
		return codecID
	default:
		return codecTransportCodec2
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

func libraryDisplayName(path string, fallback string) string {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return fallback
	}
	normalized := strings.ReplaceAll(cleaned, "\\", "/")
	name := strings.TrimSpace(pathpkg.Base(normalized))
	switch name {
	case "", ".", "/":
		return fallback
	default:
		return name
	}
}

func startupStatusLevel(message string) string {
	lower := strings.ToLower(strings.TrimSpace(message))
	if strings.Contains(lower, "succeeded") {
		return "info"
	}
	return "warn"
}

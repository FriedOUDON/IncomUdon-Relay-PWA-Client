package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	pathpkg "path"
	"sort"
	"strings"
	"sync"
	"time"
)

type sessionConfig struct {
	RelayHost         string
	RelayPort         int
	ForceRelayIPv4    bool
	HideRelayEndpoint bool
	ChannelID         uint32
	SenderID          uint32
	Password          string
	CryptoMode        cryptoMode
	CodecMode         int
	TxCodec           string
	PCMOnly           bool
	SelfMute          bool
	PacketDebug       bool
	QosEnabled        bool
	FecEnabled        bool
	Codec2LibPath     string
	OpusLibPath       string
	UplinkCodec       string
	DownlinkCodec     string
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
	onEvent       func(serverEvent)
	onPCM         func([]byte)
	onOpus        func([]byte)
	onPacketStats func(packetDebugStats)
}

// packetDebugStats is deliberately aggregate-only: it exposes timings and
// counters without forwarding packet payloads, channel credentials, or keys.
// Values are cumulative since WebSocket-session creation or the most recent
// diagnostic reset.
type packetDebugStats struct {
	UptimeMs uint64 `json:"uptimeMs"`

	BrowserUplinkPCMFrames  uint64 `json:"browserUplinkPcmFrames"`
	BrowserUplinkOpusFrames uint64 `json:"browserUplinkOpusFrames"`
	BrowserUplinkBytes      uint64 `json:"browserUplinkBytes"`

	RelayTxAudioPackets   uint64 `json:"relayTxAudioPackets"`
	RelayTxAudioBytes     uint64 `json:"relayTxAudioBytes"`
	RelayTxFecPackets     uint64 `json:"relayTxFecPackets"`
	RelayTxFecBytes       uint64 `json:"relayTxFecBytes"`
	RelayTxControlPackets uint64 `json:"relayTxControlPackets"`
	RelayTxControlBytes   uint64 `json:"relayTxControlBytes"`
	RelayTxErrors         uint64 `json:"relayTxErrors"`

	RelayRxDatagrams       uint64            `json:"relayRxDatagrams"`
	RelayRxBytes           uint64            `json:"relayRxBytes"`
	RelayRxInvalidPackets  uint64            `json:"relayRxInvalidPackets"`
	RelayRxRejectedPackets uint64            `json:"relayRxRejectedPackets"`
	RelayRxAudioPackets    uint64            `json:"relayRxAudioPackets"`
	RelayRxAudioBytes      uint64            `json:"relayRxAudioBytes"`
	RelayRxFecPackets      uint64            `json:"relayRxFecPackets"`
	RelayRxFecBytes        uint64            `json:"relayRxFecBytes"`
	RelayRxAudioBySender   map[uint32]uint64 `json:"relayRxAudioBySender,omitempty"`

	DownlinkDecodedFrames   uint64 `json:"downlinkDecodedFrames"`
	DownlinkSelfMutedFrames uint64 `json:"downlinkSelfMutedFrames"`
	DownlinkQueueDrops      uint64 `json:"downlinkQueueDrops"`
	DownlinkMixedFrames     uint64 `json:"downlinkMixedFrames"`
	DownlinkMixedInputs     uint64 `json:"downlinkMixedInputs"`
	DownlinkQueuedFrames    uint64 `json:"downlinkQueuedFrames"`
	DownlinkQueuedSenders   uint32 `json:"downlinkQueuedSenders"`
	UnsupportedFrames       uint64 `json:"unsupportedFrames"`

	BrowserDownlinkPCMFrames  uint64 `json:"browserDownlinkPcmFrames"`
	BrowserDownlinkPCMBytes   uint64 `json:"browserDownlinkPcmBytes"`
	BrowserDownlinkOpusFrames uint64 `json:"browserDownlinkOpusFrames"`
	BrowserDownlinkOpusBytes  uint64 `json:"browserDownlinkOpusBytes"`

	WebSocketQueueDepth       uint32 `json:"webSocketQueueDepth"`
	WebSocketQueuedPCMFrames  uint64 `json:"webSocketQueuedPcmFrames"`
	WebSocketQueuedPCMBytes   uint64 `json:"webSocketQueuedPcmBytes"`
	WebSocketQueuedOpusFrames uint64 `json:"webSocketQueuedOpusFrames"`
	WebSocketQueuedOpusBytes  uint64 `json:"webSocketQueuedOpusBytes"`
	WebSocketDroppedFrames    uint64 `json:"webSocketDroppedFrames"`
	WebSocketDroppedBytes     uint64 `json:"webSocketDroppedBytes"`
	WebSocketWrittenFrames    uint64 `json:"webSocketWrittenFrames"`
	WebSocketWrittenBytes     uint64 `json:"webSocketWrittenBytes"`
	WebSocketWriteErrors      uint64 `json:"webSocketWriteErrors"`
}

type peerCodecConfig struct {
	Mode    int
	PCMOnly bool
	CodecID uint8
}

type relaySession struct {
	cfg            sessionConfig
	conn           *net.UDPConn
	relayAddr      *net.UDPAddr
	relayAddrs     []*net.UDPAddr
	relayAddrIndex int
	crypto         *cryptoContext
	codec2         *codec2Engine
	opusDecoder    *opusDecoderEngine
	opusEncoder    *opusEncoderEngine
	fec            *fecEncoder
	fecDecoders    map[uint32]*fecDecoder

	cb sessionCallbacks

	sendMu sync.Mutex
	mu     sync.Mutex

	seq      uint16
	audioSeq uint16

	pttPressed    bool
	talkAllowed   bool
	currentTalker uint32
	activeTalkers map[uint32]bool

	joinRetriesLeft int
	serverLocked    bool
	pendingPCM      [][]byte
	pendingOpus     [][]byte
	txPCMBuffer     []byte
	downlinkPCM     map[uint32][]byte
	downlinkQueues  map[uint32][][]byte

	peerCodec              map[uint32]peerCodecConfig
	unsupportedFrames      map[string]struct{}
	startupWarnings        []string
	qosApplied             bool
	uplinkOpusWarned       bool
	downlinkOpusWarned     bool
	serverMultiTalkEnabled bool
	serverMaxActiveTalkers int
	packetDebug            bool
	packetStats            packetDebugStats
	startedAt              time.Time

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newRelaySession(cfg sessionConfig, cb sessionCallbacks) (*relaySession, error) {
	relayAddrs, err := resolveRelayUDPAddrs(context.Background(), cfg.RelayHost, cfg.RelayPort, cfg.ForceRelayIPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve relay address: %w", err)
	}
	relayAddr := relayAddrs[0]

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
		relayAddrs:        relayAddrs,
		crypto:            cryptoCtx,
		fec:               newFECEncoder(cfg.FecEnabled),
		cb:                cb,
		joinRetriesLeft:   5,
		activeTalkers:     make(map[uint32]bool),
		peerCodec:         make(map[uint32]peerCodecConfig),
		fecDecoders:       make(map[uint32]*fecDecoder),
		downlinkPCM:       make(map[uint32][]byte),
		downlinkQueues:    make(map[uint32][][]byte),
		unsupportedFrames: make(map[string]struct{}),
		packetDebug:       cfg.PacketDebug,
		startedAt:         time.Now(),
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

func resolveRelayUDPAddrs(ctx context.Context, host string, port int, forceIPv4 bool) ([]*net.UDPAddr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("relay host is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("relay port is out of range")
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if ip, zone := parseRelayLiteralIP(host); ip != nil {
		return buildRelayUDPAddrCandidates([]net.IPAddr{{IP: ip, Zone: zone}}, port, forceIPv4)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, err
	}
	return buildRelayUDPAddrCandidates(ipAddrs, port, forceIPv4)
}

func parseRelayLiteralIP(host string) (net.IP, string) {
	zone := ""
	if percent := strings.LastIndex(host, "%"); percent > 0 {
		zone = host[percent+1:]
		host = host[:percent]
	}
	return net.ParseIP(host), zone
}

func buildRelayUDPAddrCandidates(ipAddrs []net.IPAddr, port int, forceIPv4 bool) ([]*net.UDPAddr, error) {
	ipv6 := make([]*net.UDPAddr, 0, len(ipAddrs))
	ipv4 := make([]*net.UDPAddr, 0, len(ipAddrs))
	seen := make(map[string]struct{}, len(ipAddrs))

	for _, ipAddr := range ipAddrs {
		if ipAddr.IP == nil {
			continue
		}

		var normalized net.IP
		if ipv4Addr := ipAddr.IP.To4(); ipv4Addr != nil {
			normalized = append(net.IP(nil), ipv4Addr...)
		} else if ipv6Addr := ipAddr.IP.To16(); ipv6Addr != nil {
			normalized = append(net.IP(nil), ipv6Addr...)
		} else {
			continue
		}

		key := normalized.String() + "%" + ipAddr.Zone
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		addr := &net.UDPAddr{IP: normalized, Port: port, Zone: ipAddr.Zone}
		if normalized.To4() != nil {
			ipv4 = append(ipv4, addr)
		} else {
			ipv6 = append(ipv6, addr)
		}
	}

	if forceIPv4 {
		if len(ipv4) == 0 {
			return nil, fmt.Errorf("relay host has no IPv4 address while IPv4 is forced")
		}
		return ipv4, nil
	}

	candidates := append(ipv6, ipv4...)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("relay host resolved to no usable IP addresses")
	}
	return candidates, nil
}

func (s *relaySession) advanceRelayAddress() (from *net.UDPAddr, to *net.UDPAddr, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverLocked || len(s.relayAddrs) < 2 {
		return nil, nil, false
	}

	from = s.relayAddr
	nextIndex := (s.relayAddrIndex + 1) % len(s.relayAddrs)
	to = s.relayAddrs[nextIndex]
	if udpAddrEqual(from, to) {
		return nil, nil, false
	}
	s.relayAddrIndex = nextIndex
	s.relayAddr = to
	return from, to, true
}

func (s *relaySession) emitRelayAddressFallback(from *net.UDPAddr, to *net.UDPAddr, reason string) {
	if from == nil || to == nil {
		return
	}
	message := fmt.Sprintf("Relay address fallback: %s -> %s", from, to)
	if strings.TrimSpace(reason) != "" {
		message += fmt.Sprintf(" (%s)", reason)
	}
	log.Print(message)
	// Relay candidates can contain server-managed addresses. Keep the browser
	// notification useful without exposing those endpoint details.
	s.emitEvent(serverEvent{Type: "status", Level: "debug", Message: "Relay address fallback applied"})
}

func (s *relaySession) Start() {
	s.emitEvent(serverEvent{
		Type:      "status",
		Level:     "debug",
		Message:   fmt.Sprintf("UDP socket opened on %s", s.conn.LocalAddr()),
		ChannelID: s.cfg.ChannelID,
		SenderID:  s.cfg.SenderID,
	})

	if s.cfg.QosEnabled {
		if s.qosApplied {
			s.emitEvent(serverEvent{
				Type:    "status",
				Level:   "debug",
				Message: "Network QoS enabled (DSCP EF)",
			})
		}
	} else {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "debug",
			Message: "Network QoS disabled",
		})
	}
	if s.cfg.FecEnabled {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "debug",
			Message: "FEC enabled (TX/RX RS 2-loss parity)",
		})
	} else {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "debug",
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

	s.wg.Add(5)
	go s.readLoop()
	go s.keepaliveLoop()
	go s.joinRetryLoop()
	go s.codecLoop()
	go s.downlinkMixLoop()
	if s.packetDebug && s.cb.onPacketStats != nil {
		s.wg.Add(1)
		go s.packetDebugLoop()
	}
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
	s.downlinkQueues = nil
	s.activeTalkers = nil
	s.fecDecoders = nil
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

func (s *relaySession) packetDebugLoop() {
	defer s.wg.Done()
	// One update per second keeps diagnostics useful without adding a
	// per-packet WebSocket control message to the real-time media path.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.cb.onPacketStats != nil {
				s.cb.onPacketStats(s.packetDebugSnapshot())
			}
		}
	}
}

func (s *relaySession) packetDebugSnapshot() packetDebugStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := s.packetStats
	snapshot.UptimeMs = uint64(time.Since(s.startedAt).Milliseconds())
	snapshot.DownlinkQueuedSenders = uint32(len(s.downlinkQueues))
	snapshot.DownlinkQueuedFrames = 0
	for _, queue := range s.downlinkQueues {
		snapshot.DownlinkQueuedFrames += uint64(len(queue))
	}
	if len(s.packetStats.RelayRxAudioBySender) > 0 {
		snapshot.RelayRxAudioBySender = make(map[uint32]uint64, len(s.packetStats.RelayRxAudioBySender))
		for senderID, count := range s.packetStats.RelayRxAudioBySender {
			snapshot.RelayRxAudioBySender[senderID] = count
		}
	}
	return snapshot
}

// ResetPacketDebugStats clears aggregate diagnostics without changing media
// state. It is intentionally separate from the normal session reset paths so
// an operator can take a fresh measurement while a channel remains connected.
func (s *relaySession) ResetPacketDebugStats() {
	s.mu.Lock()
	s.packetStats = packetDebugStats{}
	s.startedAt = time.Now()
	s.mu.Unlock()
}

func (s *relaySession) noteBrowserUplink(msgType byte, bytes int) {
	if !s.packetDebug || bytes <= 0 {
		return
	}
	s.mu.Lock()
	if msgType == clientBinaryOpus {
		s.packetStats.BrowserUplinkOpusFrames++
	} else {
		s.packetStats.BrowserUplinkPCMFrames++
	}
	s.packetStats.BrowserUplinkBytes += uint64(bytes)
	s.mu.Unlock()
}

func (s *relaySession) noteRelayTx(pktType uint8, bytes int, failed bool) {
	if !s.packetDebug {
		return
	}
	s.mu.Lock()
	if failed {
		s.packetStats.RelayTxErrors++
		s.mu.Unlock()
		return
	}
	if bytes > 0 {
		switch pktType {
		case pktAudio:
			s.packetStats.RelayTxAudioPackets++
			s.packetStats.RelayTxAudioBytes += uint64(bytes)
		case pktFec:
			s.packetStats.RelayTxFecPackets++
			s.packetStats.RelayTxFecBytes += uint64(bytes)
		default:
			s.packetStats.RelayTxControlPackets++
			s.packetStats.RelayTxControlBytes += uint64(bytes)
		}
	}
	s.mu.Unlock()
}

func (s *relaySession) emitConnected() {
	effective := s.EffectiveConfig()
	codec2Ready, opusReady := detectRuntimeCodecAvailability(effective.Codec2LibPath, effective.OpusLibPath)
	qosEnabled := effective.QosEnabled
	fecEnabled := effective.FecEnabled
	relayHost := effective.RelayHost
	relayPort := effective.RelayPort
	if effective.HideRelayEndpoint {
		relayHost = ""
		relayPort = 0
	}

	s.emitEvent(serverEvent{
		Type:          "connected",
		Message:       "relay server response received",
		RelayHost:     relayHost,
		RelayPort:     relayPort,
		ChannelID:     effective.ChannelID,
		SenderID:      effective.SenderID,
		CryptoMode:    string(effective.CryptoMode),
		CodecMode:     effective.CodecMode,
		TxCodec:       effective.TxCodec,
		PCMOnly:       effective.PCMOnly,
		QosEnabled:    &qosEnabled,
		FecEnabled:    &fecEnabled,
		UplinkCodec:   effective.UplinkCodec,
		DownlinkCodec: effective.DownlinkCodec,
		Codec2Ready:   codec2Ready,
		OpusReady:     opusReady,
	})
}

func (s *relaySession) HandleBrowserBinary(payload []byte) {
	if len(payload) < 2 {
		return
	}

	msgType := payload[0]
	body := payload[1:]

	switch msgType {
	case clientBinaryAudio:
		s.noteBrowserUplink(msgType, len(body))
		s.SendPCM(body)
	case clientBinaryOpus:
		s.noteBrowserUplink(msgType, len(body))
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

// SetSelfMuted excludes frames whose relay sender ID matches this browser's
// sender ID before per-speaker buffering and the downlink mix.
func (s *relaySession) SetSelfMuted(enabled bool) {
	s.mu.Lock()
	s.cfg.SelfMute = enabled
	if enabled {
		delete(s.downlinkPCM, s.cfg.SenderID)
		delete(s.downlinkQueues, s.cfg.SenderID)
	}
	s.mu.Unlock()
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
		if s.packetDebug {
			s.mu.Lock()
			s.packetStats.RelayRxDatagrams++
			s.packetStats.RelayRxBytes += uint64(n)
			s.mu.Unlock()
		}
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
					Type:    "disconnected",
					Level:   "warn",
					Message: "No response from relay server (join retry limit reached)",
				})
				return
			}
			s.joinRetriesLeft--
			s.mu.Unlock()
			from, to, changed := s.advanceRelayAddress()
			if changed {
				s.emitRelayAddressFallback(from, to, "no response to join")
			}

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

func (s *relaySession) downlinkMixLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			frames := make([][]byte, 0)

			s.mu.Lock()
			for senderID, queue := range s.downlinkQueues {
				if len(queue) == 0 {
					delete(s.downlinkQueues, senderID)
					continue
				}
				frames = append(frames, queue[0])
				if len(queue) == 1 {
					delete(s.downlinkQueues, senderID)
				} else {
					s.downlinkQueues[senderID] = queue[1:]
				}
			}
			if s.packetDebug && len(frames) > 0 {
				s.packetStats.DownlinkMixedFrames++
				s.packetStats.DownlinkMixedInputs += uint64(len(frames))
			}
			s.mu.Unlock()

			if len(frames) == 0 {
				continue
			}

			mixed := mixPCMFrames(frames)
			if len(mixed) == 0 {
				continue
			}
			s.emitMixedDownlinkAudio(mixed)
		}
	}
}

func (s *relaySession) handleDatagram(data []byte, from *net.UDPAddr) {
	pkt, ok := parsePacket(data)
	if !ok {
		if s.packetDebug {
			s.mu.Lock()
			s.packetStats.RelayRxInvalidPackets++
			s.mu.Unlock()
		}
		return
	}
	if pkt.Header.Version != protocolVersion {
		if s.packetDebug {
			s.mu.Lock()
			s.packetStats.RelayRxInvalidPackets++
			s.mu.Unlock()
		}
		return
	}
	if pkt.Header.ChannelID != s.cfg.ChannelID {
		if s.packetDebug {
			s.mu.Lock()
			s.packetStats.RelayRxRejectedPackets++
			s.mu.Unlock()
		}
		return
	}
	if !s.acceptServerAddress(from) {
		if s.packetDebug {
			s.mu.Lock()
			s.packetStats.RelayRxRejectedPackets++
			s.mu.Unlock()
		}
		return
	}
	s.noteRelayRxPacket(pkt.Header.Type, len(data), pkt.Header.SenderID)

	switch pkt.Header.Type {
	case pktTalkGrant, pktTalkRelease, pktTalkDeny:
		s.handleTalkPacket(pkt)
	case pktCodecConfig:
		s.handleCodecConfig(pkt)
	case pktServerCfg:
		s.handleServerConfig(pkt)
	case pktAudio:
		s.handleAudioPacket(pkt)
	case pktFec:
		s.handleFecPacket(pkt)
	case pktKeyExchange:
		s.handleHandshakePacket(pkt)
	}
}

func (s *relaySession) noteRelayRxPacket(pktType uint8, bytes int, senderID uint32) {
	if !s.packetDebug || bytes <= 0 {
		return
	}
	s.mu.Lock()
	switch pktType {
	case pktAudio:
		s.packetStats.RelayRxAudioPackets++
		s.packetStats.RelayRxAudioBytes += uint64(bytes)
		if senderID != 0 {
			if s.packetStats.RelayRxAudioBySender == nil {
				s.packetStats.RelayRxAudioBySender = make(map[uint32]uint64)
			}
			if _, known := s.packetStats.RelayRxAudioBySender[senderID]; known || len(s.packetStats.RelayRxAudioBySender) < 16 {
				s.packetStats.RelayRxAudioBySender[senderID]++
			}
		}
	case pktFec:
		s.packetStats.RelayRxFecPackets++
		s.packetStats.RelayRxFecBytes += uint64(bytes)
	}
	s.mu.Unlock()
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
	senderID := s.cfg.SenderID
	s.mu.Unlock()

	log.Printf("Relay endpoint locked to %s (channel=%d sender=%d)", from, channelID, senderID)
	s.emitConnected()
	return true
}

func (s *relaySession) handleTalkPacket(pkt parsedPacket) {
	talker := readTalkerPayload(pkt.Payload, pkt.Header.SenderID)
	var flushPCM [][]byte
	var flushOpus [][]byte
	var releaseDecoder *fecDecoder
	s.mu.Lock()
	switch pkt.Header.Type {
	case pktTalkGrant:
		if talker != 0 {
			if !s.activeTalkers[talker] {
				delete(s.fecDecoders, talker)
			}
			s.activeTalkers[talker] = true
		}
	case pktTalkRelease:
		delete(s.activeTalkers, talker)
		releaseDecoder = s.fecDecoders[talker]
		delete(s.fecDecoders, talker)
	case pktTalkDeny:
		// no-op
	}

	activeTalkers := make([]uint32, 0, len(s.activeTalkers))
	for senderID := range s.activeTalkers {
		activeTalkers = append(activeTalkers, senderID)
	}
	sort.Slice(activeTalkers, func(i, j int) bool { return activeTalkers[i] < activeTalkers[j] })

	s.currentTalker = 0
	for _, senderID := range activeTalkers {
		s.currentTalker = senderID
		break
	}
	s.talkAllowed = s.activeTalkers[s.cfg.SenderID]
	if s.talkAllowed && len(s.pendingPCM) > 0 {
		flushPCM = append(flushPCM, s.pendingPCM...)
		s.pendingPCM = nil
	}
	if s.talkAllowed && len(s.pendingOpus) > 0 {
		flushOpus = append(flushOpus, s.pendingOpus...)
		s.pendingOpus = nil
	}
	talkAllowed := s.talkAllowed
	currentTalker := s.currentTalker
	s.mu.Unlock()

	if releaseDecoder != nil {
		for _, frame := range releaseDecoder.Flush() {
			s.handleCodecFrame(talker, frame.Data)
		}
	}

	s.emitEvent(serverEvent{
		Type:          "talker",
		TalkerID:      currentTalker,
		ActiveTalkers: activeTalkers,
		TalkAllowed:   talkAllowed,
	})

	if pkt.Header.Type == pktTalkDeny {
		currentTalker := talker
		if currentTalker == 0 && len(activeTalkers) > 0 {
			currentTalker = activeTalkers[0]
		}
		s.emitEvent(serverEvent{
			Type:     "status",
			Level:    "warn",
			Message:  fmt.Sprintf("PTT denied. Current talker=%d", currentTalker),
			TalkerID: currentTalker,
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
	previous, hadPrevious := s.peerCodec[pkt.Header.SenderID]
	s.peerCodec[pkt.Header.SenderID] = peerCodecConfig{
		Mode:    mode,
		PCMOnly: pcmOnly,
		CodecID: codecID,
	}
	if hadPrevious && (previous.Mode != mode || previous.PCMOnly != pcmOnly || previous.CodecID != codecID) {
		delete(s.fecDecoders, pkt.Header.SenderID)
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
	multiTalkEnabled := false
	maxActiveTalkers := uint32(1)
	if len(pkt.Payload) >= 4 {
		multiTalkEnabled = (pkt.Payload[2] & 0x01) != 0
		if pkt.Payload[3] > 0 {
			maxActiveTalkers = uint32(pkt.Payload[3])
		}
	}

	s.mu.Lock()
	s.serverMultiTalkEnabled = multiTalkEnabled
	s.serverMaxActiveTalkers = int(maxActiveTalkers)
	s.mu.Unlock()

	s.emitEvent(serverEvent{
		Type:             "server_config",
		TalkTimeoutSec:   timeoutSec,
		MultiTalkEnabled: multiTalkEnabled,
		MaxActiveTalkers: maxActiveTalkers,
	})
	if timeoutSec == 0 {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "debug",
			Message: "Server TX timeout is disabled",
		})
		return
	}
	s.emitEvent(serverEvent{
		Type:    "status",
		Level:   "debug",
		Message: fmt.Sprintf("Server TX timeout: %ds", timeoutSec),
	})
	if multiTalkEnabled {
		s.emitEvent(serverEvent{
			Type:    "status",
			Level:   "debug",
			Message: fmt.Sprintf("Server multi-talk enabled (max active talkers: %d)", maxActiveTalkers),
		})
	}
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
	plaintext, ok := s.decryptRealtimePayload(pkt)
	if !ok {
		return
	}

	audioSeq, frame, hasSequence := splitAudioPayload(plaintext)
	if len(frame) == 0 {
		return
	}
	if hasSequence && s.fecReceiveEnabled() {
		for _, recovered := range s.pushFECData(pkt.Header.SenderID, audioSeq, frame) {
			s.handleCodecFrame(pkt.Header.SenderID, recovered.Data)
		}
		return
	}
	s.handleCodecFrame(pkt.Header.SenderID, frame)
}

func (s *relaySession) handleFecPacket(pkt parsedPacket) {
	if !s.fecReceiveEnabled() {
		return
	}
	plaintext, ok := s.decryptRealtimePayload(pkt)
	if !ok || len(plaintext) < 4 {
		return
	}

	blockStart := binary.BigEndian.Uint16(plaintext[0:2])
	blockSize := plaintext[2]
	parityIndex := plaintext[3]
	parity := plaintext[4:]
	for _, recovered := range s.pushFECParity(pkt.Header.SenderID, blockStart, blockSize, parityIndex, parity) {
		s.handleCodecFrame(pkt.Header.SenderID, recovered.Data)
	}
}

func (s *relaySession) decryptRealtimePayload(pkt parsedPacket) ([]byte, bool) {
	plaintext := pkt.Payload
	s.mu.Lock()
	mode := s.cfg.CryptoMode
	s.mu.Unlock()
	if mode == cryptoNoCrypto {
		return plaintext, true
	}
	if !pkt.HasSecurity {
		return nil, false
	}

	var aad []byte
	if mode == cryptoAESGCMV2 {
		if pkt.Header.Flags&packetFlagAESGCMV2HeaderAAD == 0 || len(pkt.AAD) != fixedHeaderSize+securityHeaderSize {
			return nil, false
		}
		aad = pkt.AAD
	} else if pkt.Header.Flags&packetFlagAESGCMV2HeaderAAD != 0 {
		// Do not silently downgrade a v2 packet into a legacy AAD-free check.
		return nil, false
	}

	decoded, err := s.crypto.decrypt(pkt.Payload, pkt.Tag, pkt.Sec.Nonce, aad)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func (s *relaySession) fecReceiveEnabled() bool {
	s.mu.Lock()
	enabled := s.cfg.FecEnabled
	s.mu.Unlock()
	return enabled
}

func (s *relaySession) pushFECData(senderID uint32, audioSeq uint16, frame []byte) []fecDecodedFrame {
	decoder := s.fecDecoderFor(senderID)
	if decoder == nil {
		return nil
	}
	return decoder.PushData(audioSeq, frame)
}

func (s *relaySession) pushFECParity(senderID uint32, blockStart uint16, blockSize uint8, parityIndex uint8, data []byte) []fecDecodedFrame {
	decoder := s.fecDecoderFor(senderID)
	if decoder == nil {
		return nil
	}
	return decoder.PushParity(blockStart, blockSize, parityIndex, data)
}

func (s *relaySession) fecDecoderFor(senderID uint32) *fecDecoder {
	if senderID == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fecDecoders == nil {
		s.fecDecoders = make(map[uint32]*fecDecoder)
	}
	decoder := s.fecDecoders[senderID]
	if decoder == nil {
		decoder = newFECDecoder(s.cfg.FecEnabled)
		s.fecDecoders[senderID] = decoder
	}
	return decoder
}

func (s *relaySession) handleCodecFrame(senderID uint32, frame []byte) {
	if len(frame) == 0 {
		return
	}

	s.mu.Lock()
	peerCfg, hasPeer := s.peerCodec[senderID]
	codec := s.codec2
	opusDecoder := s.opusDecoder
	s.mu.Unlock()

	if hasPeer {
		codecID := normalizeCodecTransportID(peerCfg.CodecID, peerCfg.PCMOnly)
		switch codecID {
		case codecTransportPCM:
			s.emitDownlinkAudio(senderID, frame)
			return
		case codecTransportOpus:
			if opusDecoder == nil {
				s.emitUnsupportedFrame(senderID, len(frame), "opus decoder is unavailable")
				return
			}
			decoded, err := opusDecoder.Decode(frame)
			if err != nil {
				s.emitUnsupportedFrame(senderID, len(frame), err.Error())
				return
			}
			s.emitDownlinkAudio(senderID, decoded)
			return
		default:
			if codec == nil {
				// A peer can change its transport codec while this browser session is
				// active.  Do not let an unavailable stale Codec2 mapping suppress a
				// later PCM frame (or a newly announced Opus frame) from this sender.
				s.emitUnsupportedFrame(senderID, len(frame), "codec2 is unavailable")
				s.mu.Lock()
				delete(s.peerCodec, senderID)
				s.mu.Unlock()
			} else {
				decoded, err := codec.Decode(peerCfg.Mode, frame)
				if err == nil {
					s.emitDownlinkAudio(senderID, decoded)
					return
				}
			}
		}
	}

	if len(frame) == pcmBytesPerFrame {
		s.mu.Lock()
		s.peerCodec[senderID] = peerCodecConfig{
			Mode:    normalizeCodecModeForTransport(s.cfg.CodecMode, codecTransportPCM, true),
			PCMOnly: true,
			CodecID: codecTransportPCM,
		}
		s.mu.Unlock()
		s.emitDownlinkAudio(senderID, frame)
		return
	}

	if codec != nil {
		decoded, detectedMode, err := codec.DecodeBySize(frame)
		if err == nil {
			s.mu.Lock()
			s.peerCodec[senderID] = peerCodecConfig{
				Mode:    detectedMode,
				PCMOnly: false,
				CodecID: codecTransportCodec2,
			}
			s.mu.Unlock()
			s.emitDownlinkAudio(senderID, decoded)
			return
		}
	}

	if opusDecoder != nil {
		decoded, err := opusDecoder.Decode(frame)
		if err == nil {
			s.mu.Lock()
			s.peerCodec[senderID] = peerCodecConfig{
				Mode:    normalizeCodecModeForTransport(s.cfg.CodecMode, codecTransportOpus, false),
				PCMOnly: false,
				CodecID: codecTransportOpus,
			}
			s.mu.Unlock()
			s.emitDownlinkAudio(senderID, decoded)
			return
		}
	}

	s.emitUnsupportedFrame(senderID, len(frame), "no compatible decoder")
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
	if s.packetDebug {
		s.packetStats.UnsupportedFrames++
	}
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

func (s *relaySession) emitDownlinkAudio(senderID uint32, frame []byte) {
	s.mu.Lock()
	selfMuted := s.cfg.SelfMute && senderID == s.cfg.SenderID
	if s.packetDebug && selfMuted {
		s.packetStats.DownlinkSelfMutedFrames++
	}
	s.mu.Unlock()
	if selfMuted {
		return
	}

	frames := s.collectDownlinkPCMFrames(senderID, frame)
	if len(frames) == 0 {
		return
	}

	s.mu.Lock()
	if s.downlinkQueues == nil {
		s.downlinkQueues = make(map[uint32][][]byte)
	}
	queue := s.downlinkQueues[senderID]
	for _, pcm := range frames {
		if len(queue) >= 48 {
			queue = queue[1:]
			if s.packetDebug {
				s.packetStats.DownlinkQueueDrops++
			}
		}
		queue = append(queue, pcm)
		if s.packetDebug {
			s.packetStats.DownlinkDecodedFrames++
		}
	}
	s.downlinkQueues[senderID] = queue
	s.mu.Unlock()
}

func (s *relaySession) emitMixedDownlinkAudio(pcm []byte) {
	if len(pcm) == 0 {
		return
	}

	s.mu.Lock()
	downlinkCodec := s.cfg.DownlinkCodec
	encoder := s.opusEncoder
	warned := s.downlinkOpusWarned
	s.mu.Unlock()

	if downlinkCodec == downlinkCodecOpus && encoder != nil && s.cb.onOpus != nil {
		packet, err := encoder.Encode(pcm)
		if err == nil {
			if s.packetDebug {
				s.mu.Lock()
				s.packetStats.BrowserDownlinkOpusFrames++
				s.packetStats.BrowserDownlinkOpusBytes += uint64(len(packet))
				s.mu.Unlock()
			}
			s.cb.onOpus(packet)
			return
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
		if s.packetDebug {
			s.mu.Lock()
			s.packetStats.BrowserDownlinkPCMFrames++
			s.packetStats.BrowserDownlinkPCMBytes += uint64(len(pcm))
			s.mu.Unlock()
		}
		s.cb.onPCM(pcm)
	}
}

func (s *relaySession) collectDownlinkPCMFrames(senderID uint32, frame []byte) [][]byte {
	if senderID == 0 {
		return nil
	}

	pcm := sanitizePCM(frame)
	if len(pcm) == 0 {
		return nil
	}

	s.mu.Lock()
	buffer := s.downlinkPCM[senderID]
	if len(buffer) > pcmBytesPerFrame*64 {
		buffer = nil
	}
	buffer = append(buffer, pcm...)
	frames := make([][]byte, 0, len(buffer)/pcmBytesPerFrame+1)
	for len(buffer) >= pcmBytesPerFrame {
		out := append([]byte(nil), buffer[:pcmBytesPerFrame]...)
		frames = append(frames, out)
		buffer = buffer[pcmBytesPerFrame:]
	}
	if len(buffer) == 0 {
		delete(s.downlinkPCM, senderID)
	} else {
		s.downlinkPCM[senderID] = buffer
	}
	s.mu.Unlock()

	return frames
}

func mixPCMFrames(frames [][]byte) []byte {
	if len(frames) == 0 {
		return nil
	}

	samplesPerFrame := pcmBytesPerFrame / 2
	accum := make([]int, samplesPerFrame)
	contributors := 0

	for _, pcm := range frames {
		if len(pcm) < pcmBytesPerFrame {
			continue
		}
		contributors++
		for i := 0; i < samplesPerFrame; i++ {
			sample := int(int16(binary.LittleEndian.Uint16(pcm[i*2 : i*2+2])))
			accum[i] += sample
		}
	}

	if contributors == 0 {
		return nil
	}

	mixed := make([]byte, pcmBytesPerFrame)
	for i := 0; i < samplesPerFrame; i++ {
		value := accum[i] / contributors
		if value > 32767 {
			value = 32767
		} else if value < -32768 {
			value = -32768
		}
		binary.LittleEndian.PutUint16(mixed[i*2:i*2+2], uint16(int16(value)))
	}
	return mixed
}

func (s *relaySession) sendJoin() error {
	err := s.sendControlPacket(pktJoin, nil)
	if err == nil {
		return nil
	}

	from, to, changed := s.advanceRelayAddress()
	if !changed {
		return err
	}
	s.emitRelayAddressFallback(from, to, fmt.Sprintf("join send failed: %v", err))
	if fallbackErr := s.sendControlPacket(pktJoin, nil); fallbackErr != nil {
		return fmt.Errorf("%w; fallback join failed: %v", err, fallbackErr)
	}
	return nil
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
	s.noteRelayTx(pktType, len(packet), err != nil)
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
		flags := uint16(0)
		if mode == cryptoAESGCMV2 {
			flags |= packetFlagAESGCMV2HeaderAAD
		}
		aad := securePacketAAD(pktAudio, channelID, senderID, seq, nonce, keyID, flags)
		ciphertext, tag, err := s.crypto.encrypt(payload, nonce, aad)
		if err != nil {
			return err
		}
		packet = buildEncryptedPacket(pktAudio, channelID, senderID, seq, nonce, keyID, flags, ciphertext, tag)
	}

	_, err := s.conn.WriteToUDP(packet, addr)
	if err != nil {
		s.noteRelayTx(pktAudio, len(packet), true)
		return err
	}
	s.noteRelayTx(pktAudio, len(packet), false)

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
			flags := uint16(0)
			if mode == cryptoAESGCMV2 {
				flags |= packetFlagAESGCMV2HeaderAAD
			}
			aad := securePacketAAD(pktFec, channelID, senderID, fecSeq, fecNonce, fecKeyID, flags)
			ciphertext, tag, encErr := s.crypto.encrypt(fecPayload, fecNonce, aad)
			if encErr != nil {
				return encErr
			}
			fecPacket = buildEncryptedPacket(pktFec, channelID, senderID, fecSeq, fecNonce, fecKeyID, flags, ciphertext, tag)
		}

		if _, err := s.conn.WriteToUDP(fecPacket, addr); err != nil {
			s.noteRelayTx(pktFec, len(fecPacket), true)
			return err
		}
		s.noteRelayTx(pktFec, len(fecPacket), false)
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

func splitAudioPayload(payload []byte) (uint16, []byte, bool) {
	if len(payload) == 0 {
		return 0, nil, false
	}
	if len(payload) == pcmBytesPerFrame {
		return 0, append([]byte(nil), payload...), false
	}
	if len(payload) < 2 {
		return 0, nil, false
	}
	frame := payload[2:]
	if len(frame) == 0 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(payload[:2]), append([]byte(nil), frame...), true
}

func extractAudioFrame(payload []byte) []byte {
	_, frame, _ := splitAudioPayload(payload)
	return frame
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
		return "debug"
	}
	return "warn"
}

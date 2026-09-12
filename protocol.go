package main

import "encoding/binary"

const (
	protocolVersion = 1

	fixedHeaderSize    = 16
	legacyHeaderSize   = 14
	securityHeaderSize = 12
	authTagSize        = 16

	// Version 1 stays below the IPv6 minimum link MTU without relying on IP
	// fragmentation. The larger receive limit only bounds untrusted payloads.
	maxUDPDatagramBytes        = 1200
	maxMediaFrameBytes         = 4096
	maxTransmitMediaFrameBytes = 1131
	maxMixTalkers              = 16

	// packetFlagAESGCMV2HeaderAAD marks packets whose fixed and security
	// headers are authenticated as AES-GCM additional authenticated data.
	packetFlagAESGCMV2HeaderAAD uint16 = 1 << 0
	packetFlagControlAuthV1     uint16 = 1 << 1
)

const (
	pktAudio             = 0x01
	pktPttOn             = 0x02
	pktPttOff            = 0x03
	pktKeepalive         = 0x04
	pktJoin              = 0x05
	pktLeave             = 0x06
	pktTalkGrant         = 0x07
	pktTalkRelease       = 0x08
	pktTalkDeny          = 0x09
	pktKeyExchange       = 0x0A
	pktCodecConfig       = 0x0B
	pktFec               = 0x0C
	pktServerCfg         = 0x0D
	pktPing              = 0x0E
	pktPong              = 0x0F
	pktAuthHello         = 0x10
	pktAuthChallenge     = 0x11
	pktIdentityBegin     = 0x12
	pktIdentityChallenge = 0x13
	pktIdentityProof     = 0x14
	pktIdentityDeny      = 0x15
)

const (
	clientBinaryAudio = 0x01
	clientBinaryOpus  = 0x02
	serverBinaryAudio = 0x11
	serverBinaryOpus  = 0x12

	codecTransportPCM    = 0x00
	codecTransportCodec2 = 0x01
	codecTransportOpus   = 0x02

	pcmSamplesPerFrame = 160
	pcmBytesPerFrame   = pcmSamplesPerFrame * 2
)

type packetHeader struct {
	Version   uint8
	Type      uint8
	HeaderLen uint16
	ChannelID uint32
	SenderID  uint32
	Seq       uint16
	Flags     uint16
}

type securityHeader struct {
	Nonce          uint64
	MediaNonceBase [12]byte
	MediaCounter   uint32
	KeyID          uint32
}

type parsedPacket struct {
	Header      packetHeader
	Sec         securityHeader
	AAD         []byte
	Payload     []byte
	Tag         []byte
	HasSecurity bool
}

func parsePacket(data []byte) (parsedPacket, bool) {
	if len(data) < legacyHeaderSize {
		return parsedPacket{}, false
	}

	header := packetHeader{
		Version:   data[0],
		Type:      data[1],
		HeaderLen: binary.BigEndian.Uint16(data[2:4]),
		ChannelID: binary.BigEndian.Uint32(data[4:8]),
		SenderID:  binary.BigEndian.Uint32(data[8:12]),
		Seq:       binary.BigEndian.Uint16(data[12:14]),
	}

	offset := legacyHeaderSize
	fixedUsed := legacyHeaderSize

	if header.HeaderLen == fixedHeaderSize ||
		header.HeaderLen == fixedHeaderSize+securityHeaderSize ||
		header.HeaderLen == fixedHeaderSize+20 {
		if len(data) < fixedHeaderSize {
			return parsedPacket{}, false
		}
		header.Flags = binary.BigEndian.Uint16(data[14:16])
		offset = fixedHeaderSize
		fixedUsed = fixedHeaderSize
	}

	if int(header.HeaderLen) < fixedUsed {
		return parsedPacket{}, false
	}

	if (header.Type == pktAudio || header.Type == pktFec) && header.Flags&packetFlagAESGCMV2HeaderAAD != 0 {
		if header.HeaderLen != fixedHeaderSize+20 || len(data) < fixedHeaderSize+20+authTagSize {
			return parsedPacket{}, false
		}
		sec := securityHeader{MediaCounter: binary.BigEndian.Uint32(data[28:32]), KeyID: binary.BigEndian.Uint32(data[32:36])}
		copy(sec.MediaNonceBase[:], data[16:28])
		return parseSecurePacket(data, header, sec, fixedHeaderSize+20)
	}

	if int(header.HeaderLen) == fixedHeaderSize+securityHeaderSize {
		if len(data) < offset+securityHeaderSize+authTagSize {
			return parsedPacket{}, false
		}

		sec := securityHeader{
			Nonce: binary.BigEndian.Uint64(data[offset : offset+8]),
			KeyID: binary.BigEndian.Uint32(data[offset+8 : offset+12]),
		}
		return parseSecurePacket(data, header, sec, offset+securityHeaderSize)
	}

	if int(header.HeaderLen) != fixedUsed {
		return parsedPacket{}, false
	}

	payload := make([]byte, len(data)-offset)
	copy(payload, data[offset:])

	return parsedPacket{
		Header:      header,
		Payload:     payload,
		HasSecurity: false,
	}, true
}

func parseSecurePacket(data []byte, header packetHeader, sec securityHeader, offset int) (parsedPacket, bool) {
	payloadLen := len(data) - offset - authTagSize
	if payloadLen < 0 {
		return parsedPacket{}, false
	}
	return parsedPacket{Header: header, Sec: sec, AAD: append([]byte(nil), data[:offset]...), Payload: append([]byte(nil), data[offset:offset+payloadLen]...), Tag: append([]byte(nil), data[offset+payloadLen:]...), HasSecurity: true}, true
}

func readTalkerPayload(payload []byte, fallback uint32) uint32 {
	if len(payload) < 4 {
		return fallback
	}
	return binary.BigEndian.Uint32(payload[:4])
}

func buildNoCryptoPacket(pktType uint8, channelID uint32, senderID uint32, seq uint16, payload []byte) []byte {
	packet := make([]byte, 0, fixedHeaderSize+len(payload))
	header := make([]byte, fixedHeaderSize)
	header[0] = protocolVersion
	header[1] = pktType
	binary.BigEndian.PutUint16(header[2:4], uint16(fixedHeaderSize))
	binary.BigEndian.PutUint32(header[4:8], channelID)
	binary.BigEndian.PutUint32(header[8:12], senderID)
	binary.BigEndian.PutUint16(header[12:14], seq)
	binary.BigEndian.PutUint16(header[14:16], 0)

	packet = append(packet, header...)
	packet = append(packet, payload...)
	return packet
}

func buildPlainSecurePacket(pktType uint8, channelID uint32, senderID uint32, seq uint16, payload []byte) []byte {
	packet := buildSecurePacketPrefix(pktType, channelID, senderID, seq, 0, 0, 0)
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, authTagSize)...)
	return packet
}

func buildSecurePacketPrefix(pktType uint8, channelID uint32, senderID uint32, seq uint16, nonce uint64, keyID uint32, flags uint16) []byte {
	packet := make([]byte, 0, fixedHeaderSize+securityHeaderSize)
	header := make([]byte, fixedHeaderSize)
	header[0] = protocolVersion
	header[1] = pktType
	binary.BigEndian.PutUint16(header[2:4], uint16(fixedHeaderSize+securityHeaderSize))
	binary.BigEndian.PutUint32(header[4:8], channelID)
	binary.BigEndian.PutUint32(header[8:12], senderID)
	binary.BigEndian.PutUint16(header[12:14], seq)
	binary.BigEndian.PutUint16(header[14:16], flags)

	sec := make([]byte, securityHeaderSize)
	binary.BigEndian.PutUint64(sec[0:8], nonce)
	binary.BigEndian.PutUint32(sec[8:12], keyID)
	packet = append(packet, header...)
	packet = append(packet, sec...)
	return packet
}

func buildEncryptedPacket(pktType uint8, channelID uint32, senderID uint32, seq uint16, nonce uint64, keyID uint32, flags uint16, ciphertext []byte, tag []byte) []byte {
	packet := buildSecurePacketPrefix(pktType, channelID, senderID, seq, nonce, keyID, flags)
	packet = append(packet, ciphertext...)
	packet = append(packet, tag...)
	return packet
}

func buildAESGCMV2Packet(pktType uint8, channelID uint32, senderID uint32, seq uint16, base [12]byte, counter uint32, ciphertext []byte, tag []byte) []byte {
	packet := make([]byte, fixedHeaderSize+20+len(ciphertext)+len(tag))
	packet[0], packet[1] = protocolVersion, pktType
	binary.BigEndian.PutUint16(packet[2:4], fixedHeaderSize+20)
	binary.BigEndian.PutUint32(packet[4:8], channelID)
	binary.BigEndian.PutUint32(packet[8:12], senderID)
	binary.BigEndian.PutUint16(packet[12:14], seq)
	binary.BigEndian.PutUint16(packet[14:16], packetFlagAESGCMV2HeaderAAD)
	copy(packet[16:28], base[:])
	binary.BigEndian.PutUint32(packet[28:32], counter)
	binary.BigEndian.PutUint32(packet[32:36], 2)
	copy(packet[36:], ciphertext)
	copy(packet[36+len(ciphertext):], tag)
	return packet
}

func securePacketAAD(pktType uint8, channelID uint32, senderID uint32, seq uint16, nonce uint64, keyID uint32, flags uint16) []byte {
	if flags&packetFlagAESGCMV2HeaderAAD == 0 {
		return nil
	}
	return buildSecurePacketPrefix(pktType, channelID, senderID, seq, nonce, keyID, flags)
}

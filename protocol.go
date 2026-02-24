package main

import "encoding/binary"

const (
	protocolVersion = 1

	fixedHeaderSize    = 16
	legacyHeaderSize   = 14
	securityHeaderSize = 12
	authTagSize        = 16
)

const (
	pktAudio       = 0x01
	pktPttOn       = 0x02
	pktPttOff      = 0x03
	pktKeepalive   = 0x04
	pktJoin        = 0x05
	pktLeave       = 0x06
	pktTalkGrant   = 0x07
	pktTalkRelease = 0x08
	pktTalkDeny    = 0x09
	pktKeyExchange = 0x0A
	pktCodecConfig = 0x0B
	pktFec         = 0x0C
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
	Nonce uint64
	KeyID uint32
}

type parsedPacket struct {
	Header      packetHeader
	Sec         securityHeader
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
		header.HeaderLen == fixedHeaderSize+securityHeaderSize {
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

	if int(header.HeaderLen) >= fixedUsed+securityHeaderSize {
		if len(data) < offset+securityHeaderSize+authTagSize {
			return parsedPacket{}, false
		}

		sec := securityHeader{
			Nonce: binary.BigEndian.Uint64(data[offset : offset+8]),
			KeyID: binary.BigEndian.Uint32(data[offset+8 : offset+12]),
		}
		offset += securityHeaderSize

		payloadLen := len(data) - offset - authTagSize
		if payloadLen < 0 {
			return parsedPacket{}, false
		}

		payload := make([]byte, payloadLen)
		copy(payload, data[offset:offset+payloadLen])

		tag := make([]byte, authTagSize)
		copy(tag, data[offset+payloadLen:])

		return parsedPacket{
			Header:      header,
			Sec:         sec,
			Payload:     payload,
			Tag:         tag,
			HasSecurity: true,
		}, true
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
	packet := make([]byte, 0, fixedHeaderSize+securityHeaderSize+len(payload)+authTagSize)
	header := make([]byte, fixedHeaderSize)
	header[0] = protocolVersion
	header[1] = pktType
	binary.BigEndian.PutUint16(header[2:4], uint16(fixedHeaderSize+securityHeaderSize))
	binary.BigEndian.PutUint32(header[4:8], channelID)
	binary.BigEndian.PutUint32(header[8:12], senderID)
	binary.BigEndian.PutUint16(header[12:14], seq)
	binary.BigEndian.PutUint16(header[14:16], 0)

	packet = append(packet, header...)
	packet = append(packet, make([]byte, securityHeaderSize)...)
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, authTagSize)...)
	return packet
}

func buildEncryptedPacket(pktType uint8, channelID uint32, senderID uint32, seq uint16, nonce uint64, keyID uint32, ciphertext []byte, tag []byte) []byte {
	packet := make([]byte, 0, fixedHeaderSize+securityHeaderSize+len(ciphertext)+len(tag))
	header := make([]byte, fixedHeaderSize)
	header[0] = protocolVersion
	header[1] = pktType
	binary.BigEndian.PutUint16(header[2:4], uint16(fixedHeaderSize+securityHeaderSize))
	binary.BigEndian.PutUint32(header[4:8], channelID)
	binary.BigEndian.PutUint32(header[8:12], senderID)
	binary.BigEndian.PutUint16(header[12:14], seq)
	binary.BigEndian.PutUint16(header[14:16], 0)

	sec := make([]byte, securityHeaderSize)
	binary.BigEndian.PutUint64(sec[0:8], nonce)
	binary.BigEndian.PutUint32(sec[8:12], keyID)

	packet = append(packet, header...)
	packet = append(packet, sec...)
	packet = append(packet, ciphertext...)
	packet = append(packet, tag...)
	return packet
}

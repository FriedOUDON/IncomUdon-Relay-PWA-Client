package main

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

var controlAuthDomain = []byte("incomudon-control-auth-v1\x00")

// controlAuthContext holds only process-memory key material for one Relay
// session. It authenticates control traffic, while audio continues to use its
// separately derived media key and AES-GCM v2 envelope.
type controlAuthContext struct {
	mu sync.Mutex

	key             []byte
	keyID           uint32
	clientSessionID uint32
	nextCounter     uint32

	relayKnown      bool
	relayInstanceID uint32
	relayMaxCounter uint32
	relayWindow     uint64
}

func newControlAuthContext(password string, channelID uint32, keyID uint32) (*controlAuthContext, error) {
	passwordKey, err := derivePasswordKey(password, channelID)
	if err != nil {
		return nil, err
	}
	return newControlAuthContextFromPasswordKey(passwordKey, keyID)
}

func newControlAuthContextFromPasswordKey(passwordKey []byte, keyID uint32) (*controlAuthContext, error) {
	if keyID == 0 {
		return nil, fmt.Errorf("control authentication key ID must be non-zero")
	}
	var random [4]byte
	if _, err := io.ReadFull(crand.Reader, random[:]); err != nil {
		return nil, fmt.Errorf("generate control session ID: %w", err)
	}
	sessionID := binary.BigEndian.Uint32(random[:])
	if sessionID == 0 {
		sessionID = 1
	}
	return &controlAuthContext{
		key:             hkdfSHA256(passwordKey, nil, []byte("incomudon-control-auth-v1"), sha256.Size),
		keyID:           keyID,
		clientSessionID: sessionID,
	}, nil
}

func (c *controlAuthContext) nextClientNonce() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	nonce := uint64(c.clientSessionID)<<32 | uint64(c.nextCounter)
	c.nextCounter++
	return nonce
}

func (c *controlAuthContext) buildPacket(pktType uint8, channelID uint32, senderID uint32, seq uint16, payload []byte) []byte {
	nonce := c.nextClientNonce()
	prefix := buildSecurePacketPrefix(pktType, channelID, senderID, seq, nonce, c.keyID, packetFlagControlAuthV1)
	packet := append(prefix, payload...)
	return append(packet, c.tag(prefix, payload)...)
}

func (c *controlAuthContext) tag(prefix []byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(controlAuthDomain)
	_, _ = mac.Write(prefix)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)[:authTagSize]
}

// verifyRelayPacket checks the strict Control Authentication v1 envelope and
// maintains the required 64-counter replay window for a Relay instance.
func (c *controlAuthContext) verifyRelayPacket(pkt parsedPacket) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !pkt.HasSecurity || pkt.Header.HeaderLen != fixedHeaderSize+securityHeaderSize || pkt.Header.Flags != packetFlagControlAuthV1 || pkt.Sec.KeyID != c.keyID || pkt.Sec.Nonce == 0 || len(pkt.AAD) != fixedHeaderSize+securityHeaderSize || len(pkt.Tag) != authTagSize {
		return false
	}
	expected := c.tag(pkt.AAD, pkt.Payload)
	if subtle.ConstantTimeCompare(expected, pkt.Tag) != 1 {
		return false
	}

	instanceID := uint32(pkt.Sec.Nonce >> 32)
	counter := uint32(pkt.Sec.Nonce)
	if instanceID == 0 {
		return false
	}
	if !c.relayKnown || c.relayInstanceID != instanceID {
		c.relayKnown = true
		c.relayInstanceID = instanceID
		c.relayMaxCounter = counter
		c.relayWindow = 1
		return true
	}
	if counter > c.relayMaxCounter {
		delta := counter - c.relayMaxCounter
		if delta >= 64 {
			c.relayWindow = 1
		} else {
			c.relayWindow = c.relayWindow<<delta | 1
		}
		c.relayMaxCounter = counter
		return true
	}
	delta := c.relayMaxCounter - counter
	if delta >= 64 || c.relayWindow&(uint64(1)<<delta) != 0 {
		return false
	}
	c.relayWindow |= uint64(1) << delta
	return true
}

func isAuthenticatedControlPacket(pktType uint8) bool {
	switch pktType {
	case pktAuthChallenge, pktTalkGrant, pktTalkRelease, pktTalkDeny,
		pktServerCfg, pktPong, pktCodecConfig, pktIdentityChallenge, pktIdentityDeny:
		return true
	default:
		return false
	}
}

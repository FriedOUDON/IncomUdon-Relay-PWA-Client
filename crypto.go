package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

type cryptoMode string

const (
	cryptoNoCrypto  cryptoMode = "no-crypto"
	cryptoLegacyXor cryptoMode = "legacy-xor"
	cryptoAESGCM    cryptoMode = "aes-gcm"
	cryptoAESGCMV2  cryptoMode = "aes-gcm-v2"
)

func parseCryptoMode(value string) (cryptoMode, bool) {
	switch cryptoMode(value) {
	case cryptoNoCrypto:
		return cryptoNoCrypto, true
	case cryptoLegacyXor:
		return cryptoLegacyXor, true
	case cryptoAESGCM:
		return cryptoAESGCM, true
	case cryptoAESGCMV2:
		return cryptoAESGCMV2, true
	default:
		return "", false
	}
}

type cryptoContext struct {
	mode           cryptoMode
	key            []byte
	nonceBase      uint64
	nonceCounter   uint64
	mediaBase      [12]byte
	mediaCounter   uint32
	mediaExhausted bool
	keyID          uint32
	gcm            cipher.AEAD
}

func newCryptoContext(mode cryptoMode, password string, channelID uint32) (*cryptoContext, error) {
	if mode == cryptoNoCrypto {
		return newCryptoContextFromPasswordKey(mode, nil)
	}
	passwordKey, err := derivePasswordKey(password, channelID)
	if err != nil {
		return nil, err
	}
	return newCryptoContextFromPasswordKey(mode, passwordKey)
}

func newCryptoContextFromPasswordKey(mode cryptoMode, passwordKey []byte) (*cryptoContext, error) {
	ctx := &cryptoContext{
		mode:  mode,
		keyID: 1,
	}

	switch mode {
	case cryptoNoCrypto:
		return ctx, nil
	case cryptoLegacyXor:
		okm := hkdfSHA256(passwordKey, nil, []byte("incomudon-session"), 40)
		ctx.key = append([]byte(nil), okm[:32]...)
		ctx.nonceBase = binary.BigEndian.Uint64(okm[32:40])
		return ctx, nil
	case cryptoAESGCM, cryptoAESGCMV2:
		keyInfo := []byte("incomudon-session-aesgcm")
		if mode == cryptoAESGCMV2 {
			// Keep v2 traffic cryptographically separate from legacy AES-GCM.
			keyInfo = []byte("incomudon-session-aesgcm-v2")
			ctx.keyID = 2
		}
		ctx.key = hkdfSHA256(passwordKey, nil, keyInfo, 32)
		if mode == cryptoAESGCMV2 {
			if _, err := io.ReadFull(crand.Reader, ctx.mediaBase[:]); err != nil {
				return nil, fmt.Errorf("generate 96-bit media nonce base: %w", err)
			}
			var zero [12]byte
			if ctx.mediaBase == zero {
				ctx.mediaBase[11] = 1
			}
		} else {
			ctx.nonceBase = randomNonceBase()
		}

		block, err := aes.NewCipher(ctx.key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithNonceSize(block, 12)
		if err != nil {
			return nil, err
		}
		ctx.gcm = gcm
		return ctx, nil
	default:
		return nil, errors.New("unsupported crypto mode")
	}
}

func (c *cryptoContext) nextMediaCounter() ([12]byte, uint32, error) {
	if c.mode != cryptoAESGCMV2 {
		return [12]byte{}, 0, errors.New("media counter requires aes-gcm-v2")
	}
	if c.mediaExhausted {
		return [12]byte{}, 0, errors.New("aes-gcm-v2 media counter exhausted; reconnect required")
	}
	counter := c.mediaCounter
	if counter == ^uint32(0) {
		c.mediaExhausted = true
	} else {
		c.mediaCounter++
	}
	return c.mediaBase, counter, nil
}

func (c *cryptoContext) rotateMediaBase() error {
	if c.mode != cryptoAESGCMV2 {
		return nil
	}
	if _, err := io.ReadFull(crand.Reader, c.mediaBase[:]); err != nil {
		return err
	}
	if c.mediaBase == ([12]byte{}) {
		c.mediaBase[11] = 1
	}
	c.mediaCounter, c.mediaExhausted = 0, false
	return nil
}

func mediaNonce(base [12]byte, counter uint32) []byte {
	nonce := base
	carry := uint64(counter)
	for i := len(nonce) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(nonce[i]) + (carry & 0xff)
		nonce[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	return nonce[:]
}

func (c *cryptoContext) encryptV2(plaintext []byte, base [12]byte, counter uint32, aad []byte) ([]byte, []byte, error) {
	if c.mode != cryptoAESGCMV2 || c.gcm == nil {
		return nil, nil, errors.New("aes-gcm-v2 is not initialized")
	}
	sealed := c.gcm.Seal(nil, mediaNonce(base, counter), plaintext, aad)
	return append([]byte(nil), sealed[:len(sealed)-authTagSize]...), append([]byte(nil), sealed[len(sealed)-authTagSize:]...), nil
}

func (c *cryptoContext) decryptV2(ciphertext, tag []byte, base [12]byte, counter uint32, aad []byte) ([]byte, error) {
	if c.mode != cryptoAESGCMV2 || c.gcm == nil || len(tag) != authTagSize {
		return nil, errors.New("invalid aes-gcm-v2 packet")
	}
	return c.gcm.Open(nil, mediaNonce(base, counter), append(append([]byte(nil), ciphertext...), tag...), aad)
}

func (c *cryptoContext) nextNonce() uint64 {
	nonce := c.nonceBase + c.nonceCounter
	c.nonceCounter++
	return nonce
}

func (c *cryptoContext) encrypt(plaintext []byte, nonce uint64, aad []byte) ([]byte, []byte, error) {
	switch c.mode {
	case cryptoNoCrypto:
		ct := append([]byte(nil), plaintext...)
		return ct, nil, nil
	case cryptoLegacyXor:
		ciphertext := xorBytes(plaintext, c.key)
		tag := legacyTag(c.key, ciphertext, nonce, aad)
		return ciphertext, tag, nil
	case cryptoAESGCM, cryptoAESGCMV2:
		if c.gcm == nil {
			return nil, nil, errors.New("aes-gcm is not initialized")
		}
		nonceBytes := make([]byte, 12)
		binary.BigEndian.PutUint64(nonceBytes[4:], nonce)
		sealed := c.gcm.Seal(nil, nonceBytes, plaintext, aad)
		if len(sealed) < authTagSize {
			return nil, nil, errors.New("invalid sealed payload")
		}
		ciphertext := append([]byte(nil), sealed[:len(sealed)-authTagSize]...)
		tag := append([]byte(nil), sealed[len(sealed)-authTagSize:]...)
		return ciphertext, tag, nil
	default:
		return nil, nil, errors.New("unsupported crypto mode")
	}
}

func (c *cryptoContext) decrypt(ciphertext []byte, tag []byte, nonce uint64, aad []byte) ([]byte, error) {
	switch c.mode {
	case cryptoNoCrypto:
		return append([]byte(nil), ciphertext...), nil
	case cryptoLegacyXor:
		expected := legacyTag(c.key, ciphertext, nonce, aad)
		if !hmac.Equal(expected, tag) {
			return nil, errors.New("legacy tag mismatch")
		}
		return xorBytes(ciphertext, c.key), nil
	case cryptoAESGCM, cryptoAESGCMV2:
		if c.gcm == nil {
			return nil, errors.New("aes-gcm is not initialized")
		}
		if len(tag) != authTagSize {
			return nil, errors.New("invalid aes-gcm tag")
		}
		nonceBytes := make([]byte, 12)
		binary.BigEndian.PutUint64(nonceBytes[4:], nonce)
		sealed := make([]byte, 0, len(ciphertext)+len(tag))
		sealed = append(sealed, ciphertext...)
		sealed = append(sealed, tag...)
		plaintext, err := c.gcm.Open(nil, nonceBytes, sealed, aad)
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	default:
		return nil, errors.New("unsupported crypto mode")
	}
}

func derivePasswordKey(credential string, channelID uint32) ([]byte, error) {
	if credential == "" {
		return nil, errors.New("secure crypto modes require a channel credential")
	}
	if strings.HasPrefix(credential, "sha256:") {
		return nil, errors.New("sha256: credentials are no longer supported")
	}
	channel := make([]byte, 4)
	binary.BigEndian.PutUint32(channel, channelID)
	h := sha256.New()
	h.Write([]byte("incomudon-channel-password-salt-v1\x00"))
	h.Write(channel)
	salt := h.Sum(nil)[:16]
	if strings.HasPrefix(credential, "secret:") {
		secret, err := hex.DecodeString(strings.TrimPrefix(credential, "secret:"))
		if err != nil || len(secret) != 32 {
			return nil, errors.New("secret: credential must contain exactly 64 hexadecimal characters")
		}
		return hkdfSHA256(secret, salt, []byte("incomudon-raw-secret-v1"), 32), nil
	}
	return argon2.IDKey([]byte(norm.NFC.String(credential)), salt, 3, 65536, 4, 32), nil
}

func hkdfSHA256(ikm []byte, salt []byte, info []byte, length int) []byte {
	prkMAC := hmac.New(sha256.New, salt)
	_, _ = prkMAC.Write(ikm)
	prk := prkMAC.Sum(nil)

	okm := make([]byte, 0, length)
	var t []byte
	counter := byte(1)
	for len(okm) < length {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(t)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
		counter++
	}

	return okm[:length]
}

func xorBytes(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), data...)
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func legacyTag(key []byte, ciphertext []byte, nonce uint64, aad []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(key)
	_, _ = h.Write(aad)
	_, _ = h.Write(ciphertext)

	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)
	_, _ = h.Write(nonceBytes[:])

	sum := h.Sum(nil)
	return append([]byte(nil), sum[:authTagSize]...)
}

func randomNonceBase() uint64 {
	var b [8]byte
	if _, err := io.ReadFull(crand.Reader, b[:]); err != nil {
		return 1
	}
	return binary.BigEndian.Uint64(b[:])
}

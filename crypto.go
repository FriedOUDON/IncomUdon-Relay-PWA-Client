package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

type cryptoMode string

const (
	cryptoNoCrypto  cryptoMode = "no-crypto"
	cryptoLegacyXor cryptoMode = "legacy-xor"
	cryptoAESGCM    cryptoMode = "aes-gcm"
)

func parseCryptoMode(value string) (cryptoMode, bool) {
	switch cryptoMode(value) {
	case cryptoNoCrypto:
		return cryptoNoCrypto, true
	case cryptoLegacyXor:
		return cryptoLegacyXor, true
	case cryptoAESGCM:
		return cryptoAESGCM, true
	default:
		return "", false
	}
}

type cryptoContext struct {
	mode         cryptoMode
	key          []byte
	nonceBase    uint64
	nonceCounter uint64
	keyID        uint32
	gcm          cipher.AEAD
}

func newCryptoContext(mode cryptoMode, password string, channelID uint32) (*cryptoContext, error) {
	ctx := &cryptoContext{
		mode:  mode,
		keyID: 1,
	}

	switch mode {
	case cryptoNoCrypto:
		return ctx, nil
	case cryptoLegacyXor:
		passwordKey := derivePasswordKey(password, channelID)
		okm := hkdfSHA256(passwordKey, nil, []byte("incomudon-session"), 40)
		ctx.key = append([]byte(nil), okm[:32]...)
		ctx.nonceBase = binary.BigEndian.Uint64(okm[32:40])
		return ctx, nil
	case cryptoAESGCM:
		passwordKey := derivePasswordKey(password, channelID)
		ctx.key = hkdfSHA256(passwordKey, nil, []byte("incomudon-session-aesgcm"), 32)
		ctx.nonceBase = randomNonceBase()

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
	case cryptoAESGCM:
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
	case cryptoAESGCM:
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

func derivePasswordKey(password string, channelID uint32) []byte {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, channelID)

	input := make([]byte, 0, len(password)+len(salt))
	input = append(input, []byte(password)...)
	input = append(input, salt...)

	sum := sha256.Sum256(input)
	return sum[:]
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

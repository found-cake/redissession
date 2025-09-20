package redissession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Crypto struct {
	aead       cipher.AEAD
	signingKey []byte
}

func NewCrypto(aead cipher.AEAD, signingKey []byte) *Crypto {
	return &Crypto{
		aead:       aead,
		signingKey: signingKey,
	}
}

func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %w", err)
	}

	return aead, nil
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %w", err)
	}

	return aead, nil
}

func NewXChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	return aead, nil
}

func (c *Crypto) GenerateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (c *Crypto) EncryptAndSign(data interface{}, aad []byte) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nonce, nonce, jsonData, aad)

	if c.signingKey != nil {
		signature := c.sign(ciphertext)
		combined := append(signature, ciphertext...)
		return base64.StdEncoding.EncodeToString(combined), nil
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *Crypto) DecryptAndVerify(encryptedData string, dest interface{}, aad []byte) error {
	decoded, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %w", err)
	}
	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()
	if c.signingKey != nil {
		minLength := 32 + nonceSize + overhead + 1
		if len(decoded) < minLength {
			return ErrInvalidSessionData
		}
		signature := decoded[:32]
		ciphertext := decoded[32:]
		if !c.verify(ciphertext, signature) {
			return ErrSignatureInvalid
		}
		decoded = ciphertext
	} else {
		minLength := nonceSize + overhead + 1
		if len(decoded) < minLength {
			return ErrInvalidSessionData
		}
	}
	nonce := decoded[:nonceSize]
	ciphertext := decoded[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return ErrEncryptionFailed
	}
	if err := json.Unmarshal(plaintext, dest); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}

func (c *Crypto) sign(data []byte) []byte {
	h := hmac.New(sha256.New, c.signingKey)
	h.Write(data)
	return h.Sum(nil)
}

func (c *Crypto) verify(data, signature []byte) bool {
	expected := c.sign(data)
	return subtle.ConstantTimeCompare(signature, expected) == 1
}

func GenerateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

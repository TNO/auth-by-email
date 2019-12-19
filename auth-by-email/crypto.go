package authbyemail

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
)

type Crypto struct {
	hmac   hash.Hash
	cipher cipher.AEAD
}

var CRYPTO *Crypto

// InitializeCrypto initializes the global CRYPTO struct with an hmac function and a
// block cipher. It uses the key in the environment variable AUTH_BY_EMAIL_KEY and
// panics if that variable is not present or not properly defined.
//
// The keys for the cipher and the hmac function are each derived from the given key
// using a hmac function with a fixed key.
func InitializeCrypto() {
	// Do nothing if this is called more than once
	if CRYPTO != nil {
		return
	}

	hexkey, ok := os.LookupEnv("AUTH_BY_EMAIL_KEY")
	if (!ok) || len(hexkey) != 64 {
		panic("No hex-encoded 32-byte key in env! please set AUTH_BY_EMAIL_KEY")
	}

	mainKey, err := hex.DecodeString(hexkey)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(keyDerivation(mainKey, []byte("aeadKey")))
	if err != nil {
		panic(err)
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	CRYPTO = &Crypto{
		hmac:   hmac.New(sha256.New, keyDerivation(mainKey, []byte("hmacKey"))),
		cipher: cipher,
	}
}

// Encrypt takes a string, encrypts it, and returns the result printed as base64
func (c *Crypto) encrypt(input string) string {
	plaintext := []byte(input)

	nonce := make([]byte, c.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	ciphertext := c.cipher.Seal(nil, nonce, plaintext, nil)

	return base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
}

// Decrypt takes a string of bytes represented by base64 encoded bytes, decrypts it,
// and returns the result as a string if this conversion is valid
func (c *Crypto) decrypt(input string) (string, error) {
	buffer, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	if len(buffer) < c.cipher.NonceSize() {
		return "", errors.New("decrypt: ciphertext is too short")
	}

	nonce, ciphertext := buffer[:c.cipher.NonceSize()], buffer[c.cipher.NonceSize():]

	plaintext, err := c.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// computeHmac uses a sha256-based hmac function to calculate the hmac of the input.
func (c *Crypto) computeHmac(input []byte) string {
	c.hmac.Reset()
	c.hmac.Write(input)
	return base64.RawURLEncoding.EncodeToString(c.hmac.Sum(nil))
}

// keyDerivation derives a new sub-key from a master key. We use different keys
// for the different cryptographic elements, and these are derived by this function
// using a temporary hmac function.
func keyDerivation(mainKey, seed []byte) []byte {
	hash := hmac.New(sha256.New, seed)
	hash.Write(mainKey)
	return hash.Sum(nil)
}

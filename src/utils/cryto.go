package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"yuudi/qrcodebook/src/config"
)

var cluster_secret_key [32]byte

func InitKey() {
	stringKey := []byte(config.AppConfig.ClusterSecretKey)
	shaKey := sha256.Sum256(stringKey)
	copy(cluster_secret_key[:], shaKey[:])
}

func GenerateCryptoRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func HmacSign(data []byte) []byte {
	h := hmac.New(sha256.New, cluster_secret_key[:])
	h.Write(data)
	return h.Sum(nil)
}

func HmacVerify(data, signature []byte) bool {
	expectedSig := HmacSign(data)
	return hmac.Equal(expectedSig, signature)
}

func Encrypt(data []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce, err := GenerateCryptoRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func Decrypt(ciphertext []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check minimum length (nonce + some data)
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

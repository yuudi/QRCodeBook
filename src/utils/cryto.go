package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func GenerateCryptoRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Encrypt(data []byte, key [32]byte) ([]byte, error) {
	paddedData := Pad(data, aes.BlockSize)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	// include iv at the beginning of the ciphertext
	iv, err := GenerateCryptoRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(paddedData))
	copy(ciphertext[:aes.BlockSize], iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedData)
	return ciphertext, nil
}

func Decrypt(ciphertext []byte, key [32]byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	paddedData := make([]byte, len(ciphertext))
	mode.CryptBlocks(paddedData, ciphertext)
	unpaddedData, err := Unpad(paddedData)
	if err != nil {
		return nil, err
	}
	return unpaddedData, nil
}

func Pad(data []byte, blockSize int) []byte {
	// PKCS#7
	paddingLength := blockSize - len(data)%blockSize
	if paddingLength == 0 {
		paddingLength = blockSize
	}
	padText := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)
	return append(data, padText...)
}

func Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	padding := data[len(data)-1]
	if int(padding) > len(data) {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-int(padding)], nil
}

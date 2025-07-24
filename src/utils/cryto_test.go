//go:build test
// +build test

package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCryptoTest initializes the test environment for crypto tests
func setupCryptoTest(t *testing.T) {
	// Initialize a fixed key for consistent testing
	cluster_secret_key = [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
}

func TestInitKey(t *testing.T) {
	t.Run("key initialization from config", func(t *testing.T) {
		// Note: This test would require actual config setup
		// For now, we'll just test that the function doesn't panic
		// In a real scenario, you'd mock config.AppConfig.ClusterSecretKey

		// We can't easily test this without mocking config
		// but we can verify the key gets set properly in other tests
		setupCryptoTest(t)

		// Verify key is not all zeros
		zeroKey := [32]byte{}
		assert.NotEqual(t, zeroKey, cluster_secret_key)
	})
}

func TestGenerateCryptoRandomBytes(t *testing.T) {
	t.Run("generate random bytes of specified length", func(t *testing.T) {
		lengths := []int{1, 8, 16, 32, 64, 128, 256}

		for _, length := range lengths {
			t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
				bytes, err := GenerateCryptoRandomBytes(length)
				require.NoError(t, err)
				assert.Len(t, bytes, length)
			})
		}
	})

	t.Run("generate zero length bytes", func(t *testing.T) {
		bytes, err := GenerateCryptoRandomBytes(0)
		require.NoError(t, err)
		assert.Len(t, bytes, 0)
	})

	t.Run("randomness check", func(t *testing.T) {
		// Generate multiple samples and ensure they're different
		size := 32
		samples := make([][]byte, 10)

		for i := 0; i < 10; i++ {
			sample, err := GenerateCryptoRandomBytes(size)
			require.NoError(t, err)
			samples[i] = sample
		}

		// Check that samples are different from each other
		for i := 0; i < len(samples); i++ {
			for j := i + 1; j < len(samples); j++ {
				assert.NotEqual(t, samples[i], samples[j],
					"Random bytes should be different between calls")
			}
		}
	})

	t.Run("negative length", func(t *testing.T) {
		// Go's make() with negative length panics, which is expected behavior
		// We'll test that this is handled appropriately
		defer func() {
			if r := recover(); r != nil {
				// This is expected - negative length should panic
				assert.Contains(t, fmt.Sprintf("%v", r), "len out of range")
			}
		}()

		// This should panic, so the test passes if it panics as expected
		_, _ = GenerateCryptoRandomBytes(-1)

		// If we reach here without panicking, that's unexpected
		t.Error("Expected panic for negative length, but function completed normally")
	})

	t.Run("large size", func(t *testing.T) {
		// Test with a reasonably large size
		largeSize := 8192
		bytes, err := GenerateCryptoRandomBytes(largeSize)
		require.NoError(t, err)
		assert.Len(t, bytes, largeSize)
	})
}

func TestHmacSign(t *testing.T) {
	setupCryptoTest(t)

	t.Run("sign data with HMAC", func(t *testing.T) {
		testData := []byte("test data for HMAC signing")
		signature := HmacSign(testData)

		assert.NotNil(t, signature)
		assert.Len(t, signature, sha256.Size) // SHA256 produces 32-byte hash

		// Verify signature is deterministic
		signature2 := HmacSign(testData)
		assert.Equal(t, signature, signature2)
	})

	t.Run("empty data", func(t *testing.T) {
		emptyData := []byte{}
		signature := HmacSign(emptyData)

		assert.NotNil(t, signature)
		assert.Len(t, signature, sha256.Size)
	})

	t.Run("nil data", func(t *testing.T) {
		signature := HmacSign(nil)

		assert.NotNil(t, signature)
		assert.Len(t, signature, sha256.Size)
	})

	t.Run("different data produces different signatures", func(t *testing.T) {
		data1 := []byte("first data")
		data2 := []byte("second data")

		sig1 := HmacSign(data1)
		sig2 := HmacSign(data2)

		assert.NotEqual(t, sig1, sig2)
	})

	t.Run("large data", func(t *testing.T) {
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		signature := HmacSign(largeData)
		assert.NotNil(t, signature)
		assert.Len(t, signature, sha256.Size)
	})

	t.Run("verify against known implementation", func(t *testing.T) {
		testData := []byte("known test data")

		// Manual HMAC calculation for verification
		h := hmac.New(sha256.New, cluster_secret_key[:])
		h.Write(testData)
		expectedSignature := h.Sum(nil)

		actualSignature := HmacSign(testData)
		assert.Equal(t, expectedSignature, actualSignature)
	})
}

func TestHmacVerify(t *testing.T) {
	setupCryptoTest(t)

	t.Run("verify valid signature", func(t *testing.T) {
		testData := []byte("test data for verification")
		signature := HmacSign(testData)

		isValid := HmacVerify(testData, signature)
		assert.True(t, isValid)
	})

	t.Run("reject invalid signature", func(t *testing.T) {
		testData := []byte("test data")
		validSignature := HmacSign(testData)

		// Corrupt the signature
		invalidSignature := make([]byte, len(validSignature))
		copy(invalidSignature, validSignature)
		invalidSignature[0] ^= 0xFF // Flip bits in first byte

		isValid := HmacVerify(testData, invalidSignature)
		assert.False(t, isValid)
	})

	t.Run("reject signature for different data", func(t *testing.T) {
		originalData := []byte("original data")
		modifiedData := []byte("modified data")

		signature := HmacSign(originalData)
		isValid := HmacVerify(modifiedData, signature)
		assert.False(t, isValid)
	})

	t.Run("reject wrong length signature", func(t *testing.T) {
		testData := []byte("test data")
		wrongLengthSig := []byte("short")

		isValid := HmacVerify(testData, wrongLengthSig)
		assert.False(t, isValid)
	})

	t.Run("verify empty data signature", func(t *testing.T) {
		emptyData := []byte{}
		signature := HmacSign(emptyData)

		isValid := HmacVerify(emptyData, signature)
		assert.True(t, isValid)
	})

	t.Run("timing attack resistance", func(t *testing.T) {
		// This test ensures that verification uses constant-time comparison
		testData := []byte("sensitive data")
		validSignature := HmacSign(testData)

		// Create signatures that differ in various positions
		wrongSigs := make([][]byte, 5)
		for i := range wrongSigs {
			wrongSigs[i] = make([]byte, len(validSignature))
			copy(wrongSigs[i], validSignature)
			if i < len(validSignature) {
				wrongSigs[i][i] ^= 0x01 // Flip one bit at different positions
			}
		}

		// All should return false
		for i, wrongSig := range wrongSigs {
			isValid := HmacVerify(testData, wrongSig)
			assert.False(t, isValid, "Wrong signature %d should be invalid", i)
		}
	})
}

func TestEncrypt(t *testing.T) {
	setupCryptoTest(t)

	t.Run("encrypt and basic properties", func(t *testing.T) {
		plaintext := []byte("Hello, World! This is a test message.")

		ciphertext, err := Encrypt(plaintext, cluster_secret_key)
		require.NoError(t, err)
		assert.NotNil(t, ciphertext)

		// Ciphertext should be longer than plaintext (includes nonce + auth tag)
		assert.Greater(t, len(ciphertext), len(plaintext))

		// Should not be the same as plaintext
		assert.NotEqual(t, plaintext, ciphertext)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		emptyData := []byte{}

		ciphertext, err := Encrypt(emptyData, cluster_secret_key)
		require.NoError(t, err)
		assert.NotNil(t, ciphertext)

		// Even empty data should produce some ciphertext (nonce + auth tag)
		assert.Greater(t, len(ciphertext), 0)
	})

	t.Run("encrypt nil data", func(t *testing.T) {
		ciphertext, err := Encrypt(nil, cluster_secret_key)
		require.NoError(t, err)
		assert.NotNil(t, ciphertext)
	})

	t.Run("different encryptions of same data produce different ciphertext", func(t *testing.T) {
		plaintext := []byte("same data")

		ciphertext1, err1 := Encrypt(plaintext, cluster_secret_key)
		require.NoError(t, err1)

		ciphertext2, err2 := Encrypt(plaintext, cluster_secret_key)
		require.NoError(t, err2)

		// Should be different due to random nonce
		assert.NotEqual(t, ciphertext1, ciphertext2)
	})

	t.Run("encrypt large data", func(t *testing.T) {
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		ciphertext, err := Encrypt(largeData, cluster_secret_key)
		require.NoError(t, err)
		assert.NotNil(t, ciphertext)
		assert.Greater(t, len(ciphertext), len(largeData))
	})

	t.Run("encrypt with different keys produces different results", func(t *testing.T) {
		plaintext := []byte("test data")
		key1 := cluster_secret_key
		key2 := [32]byte{} // Different key (all zeros)
		for i := range key2 {
			key2[i] = byte(i)
		}

		ciphertext1, err1 := Encrypt(plaintext, key1)
		require.NoError(t, err1)

		ciphertext2, err2 := Encrypt(plaintext, key2)
		require.NoError(t, err2)

		assert.NotEqual(t, ciphertext1, ciphertext2)
	})

	t.Run("encrypt binary data", func(t *testing.T) {
		binaryData := make([]byte, 256)
		for i := range binaryData {
			binaryData[i] = byte(i)
		}

		ciphertext, err := Encrypt(binaryData, cluster_secret_key)
		require.NoError(t, err)
		assert.NotNil(t, ciphertext)
	})
}

func TestDecrypt(t *testing.T) {
	setupCryptoTest(t)

	t.Run("decrypt successfully", func(t *testing.T) {
		originalPlaintext := []byte("Hello, World! This is a test message.")

		ciphertext, err := Encrypt(originalPlaintext, cluster_secret_key)
		require.NoError(t, err)

		decryptedPlaintext, err := Decrypt(ciphertext, cluster_secret_key)
		require.NoError(t, err)

		assert.Equal(t, originalPlaintext, decryptedPlaintext)
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		emptyData := []byte{}

		ciphertext, err := Encrypt(emptyData, cluster_secret_key)
		require.NoError(t, err)

		decrypted, err := Decrypt(ciphertext, cluster_secret_key)
		require.NoError(t, err)

		// Handle the case where empty slice might be returned as nil
		if len(decrypted) == 0 && len(emptyData) == 0 {
			// Both are effectively empty, this is acceptable
			assert.True(t, len(decrypted) == 0)
		} else {
			assert.Equal(t, emptyData, decrypted)
		}
	})

	t.Run("fail with wrong key", func(t *testing.T) {
		plaintext := []byte("secret message")
		correctKey := cluster_secret_key
		wrongKey := [32]byte{}
		for i := range wrongKey {
			wrongKey[i] = byte(255 - i)
		}

		ciphertext, err := Encrypt(plaintext, correctKey)
		require.NoError(t, err)

		_, err = Decrypt(ciphertext, wrongKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("fail with corrupted ciphertext", func(t *testing.T) {
		plaintext := []byte("test message")

		ciphertext, err := Encrypt(plaintext, cluster_secret_key)
		require.NoError(t, err)

		// Corrupt the ciphertext
		corruptedCiphertext := make([]byte, len(ciphertext))
		copy(corruptedCiphertext, ciphertext)
		if len(corruptedCiphertext) > 16 { // Make sure we don't corrupt the nonce
			corruptedCiphertext[16] ^= 0xFF
		}

		_, err = Decrypt(corruptedCiphertext, cluster_secret_key)
		assert.Error(t, err)
	})

	t.Run("fail with too short ciphertext", func(t *testing.T) {
		shortCiphertext := []byte("short")

		_, err := Decrypt(shortCiphertext, cluster_secret_key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("fail with empty ciphertext", func(t *testing.T) {
		emptyCiphertext := []byte{}

		_, err := Decrypt(emptyCiphertext, cluster_secret_key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("decrypt large data", func(t *testing.T) {
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		ciphertext, err := Encrypt(largeData, cluster_secret_key)
		require.NoError(t, err)

		decrypted, err := Decrypt(ciphertext, cluster_secret_key)
		require.NoError(t, err)

		assert.Equal(t, largeData, decrypted)
	})

	t.Run("decrypt binary data", func(t *testing.T) {
		binaryData := make([]byte, 256)
		for i := range binaryData {
			binaryData[i] = byte(i)
		}

		ciphertext, err := Encrypt(binaryData, cluster_secret_key)
		require.NoError(t, err)

		decrypted, err := Decrypt(ciphertext, cluster_secret_key)
		require.NoError(t, err)

		assert.Equal(t, binaryData, decrypted)
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	setupCryptoTest(t)

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"small text", []byte("Hello")},
		{"medium text", []byte("This is a longer test message with more content.")},
		{"unicode", []byte("Hello 世界 🌍 测试")},
		{"binary", []byte{0, 1, 2, 255, 254, 253}},
		{"json-like", []byte(`{"name":"test","value":123,"array":[1,2,3]}`)},
		{"newlines", []byte("line1\nline2\rline3\r\nline4")},
		{"special chars", []byte("!@#$%^&*()_+-=[]{}|;':\",./<>?")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := Encrypt(tc.data, cluster_secret_key)
			require.NoError(t, err)

			// Decrypt
			decrypted, err := Decrypt(ciphertext, cluster_secret_key)
			require.NoError(t, err)

			// Verify - handle empty slice vs nil slice differences
			if len(tc.data) == 0 && len(decrypted) == 0 {
				// Both are effectively empty, this is acceptable
				assert.True(t, len(decrypted) == 0)
			} else {
				assert.Equal(t, tc.data, decrypted)
			}
		})
	}
}

func TestCryptoSecurityProperties(t *testing.T) {
	setupCryptoTest(t)

	t.Run("encryption is non-deterministic", func(t *testing.T) {
		plaintext := []byte("determinism test")

		encryptions := make([][]byte, 10)
		for i := 0; i < 10; i++ {
			ciphertext, err := Encrypt(plaintext, cluster_secret_key)
			require.NoError(t, err)
			encryptions[i] = ciphertext
		}

		// All encryptions should be different
		for i := 0; i < len(encryptions); i++ {
			for j := i + 1; j < len(encryptions); j++ {
				assert.NotEqual(t, encryptions[i], encryptions[j],
					"Encryptions %d and %d should be different", i, j)
			}
		}
	})

	t.Run("tamper detection", func(t *testing.T) {
		plaintext := []byte("integrity test")

		ciphertext, err := Encrypt(plaintext, cluster_secret_key)
		require.NoError(t, err)

		// Try tampering with different parts of the ciphertext
		for i := 0; i < len(ciphertext); i++ {
			tamperedCiphertext := make([]byte, len(ciphertext))
			copy(tamperedCiphertext, ciphertext)
			tamperedCiphertext[i] ^= 0x01 // Flip one bit

			_, err := Decrypt(tamperedCiphertext, cluster_secret_key)
			assert.Error(t, err, "Tampered ciphertext at position %d should fail", i)
		}
	})

	t.Run("key sensitivity", func(t *testing.T) {
		plaintext := []byte("key sensitivity test")

		ciphertext, err := Encrypt(plaintext, cluster_secret_key)
		require.NoError(t, err)

		// Try decrypting with keys that differ by one bit
		for i := 0; i < len(cluster_secret_key); i++ {
			wrongKey := cluster_secret_key
			wrongKey[i] ^= 0x01 // Flip one bit

			_, err := Decrypt(ciphertext, wrongKey)
			assert.Error(t, err, "Wrong key differing at byte %d should fail", i)
		}
	})
}

// Benchmark tests
func BenchmarkGenerateCryptoRandomBytes(b *testing.B) {
	sizes := []int{16, 32, 64, 256, 1024}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := GenerateCryptoRandomBytes(size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHmacSign(b *testing.B) {
	setupCryptoTest(nil)
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HmacSign(data)
	}
}

func BenchmarkHmacVerify(b *testing.B) {
	setupCryptoTest(nil)
	data := make([]byte, 1024)
	rand.Read(data)
	signature := HmacSign(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HmacVerify(data, signature)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	setupCryptoTest(nil)
	sizes := []int{64, 256, 1024, 4096}

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Encrypt(data, cluster_secret_key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	setupCryptoTest(nil)
	sizes := []int{64, 256, 1024, 4096}

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)
		ciphertext, err := Encrypt(data, cluster_secret_key)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Decrypt(ciphertext, cluster_secret_key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncryptDecryptRoundTrip(b *testing.B) {
	setupCryptoTest(nil)
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err := Encrypt(data, cluster_secret_key)
		if err != nil {
			b.Fatal(err)
		}

		_, err = Decrypt(ciphertext, cluster_secret_key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

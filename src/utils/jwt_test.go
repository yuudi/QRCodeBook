//go:build test
// +build test

package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestData represents test data structure for encrypted JWT tests
type TestData struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
	ID   string `json:"id"`
}

// setupTest initializes the test environment
func setupTest(t *testing.T) {
	// Initialize the cluster secret key for testing
	// In real tests, you might want to use a known test key
	cluster_secret_key = [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
}

func TestGenerateJWT(t *testing.T) {
	setupTest(t)

	t.Run("successful token generation", func(t *testing.T) {
		claims := ValueClaim{
			Value: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "test-issuer",
				Subject:   "test-subject",
			},
		}

		token, err := GenerateJWT(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Contains(t, token, ".") // JWT should contain dots
	})

	t.Run("empty value claim", func(t *testing.T) {
		claims := ValueClaim{
			Value: "",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token, err := GenerateJWT(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestParseJWT(t *testing.T) {
	setupTest(t)

	t.Run("successful token parsing", func(t *testing.T) {
		originalClaims := ValueClaim{
			Value: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "test-issuer",
				Subject:   "test-subject",
			},
		}

		// Generate token first
		token, err := GenerateJWT(originalClaims)
		require.NoError(t, err)

		// Parse the token
		parsedClaims, err := ParseJWT(token)
		require.NoError(t, err)
		assert.Equal(t, originalClaims.Value, parsedClaims.Value)
		assert.Equal(t, originalClaims.Issuer, parsedClaims.Issuer)
		assert.Equal(t, originalClaims.Subject, parsedClaims.Subject)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := ParseJWT("invalid.token.string")
		assert.Error(t, err)
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := ParseJWT("")
		assert.Error(t, err)
	})

	t.Run("malformed token", func(t *testing.T) {
		_, err := ParseJWT("not-a-jwt-token")
		assert.Error(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		expiredClaims := ValueClaim{
			Value: "test-value",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired 1 hour ago
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
		}

		token, err := GenerateJWT(expiredClaims)
		require.NoError(t, err)

		_, err = ParseJWT(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestGenerateEncryptedJWT(t *testing.T) {
	setupTest(t)

	t.Run("successful encrypted token generation", func(t *testing.T) {
		testData := TestData{
			Name: "John Doe",
			Age:  30,
			ID:   "user-123",
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "test-issuer",
		}

		token, err := GenerateEncryptedJWT(testData, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Contains(t, token, ".") // JWT should contain dots
	})

	t.Run("nil value", func(t *testing.T) {
		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}

		token, err := GenerateEncryptedJWT(nil, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("complex nested structure", func(t *testing.T) {
		complexData := map[string]interface{}{
			"user": map[string]interface{}{
				"name": "Jane Doe",
				"details": map[string]interface{}{
					"age":     25,
					"city":    "New York",
					"hobbies": []string{"reading", "coding", "hiking"},
				},
			},
			"permissions": []string{"read", "write", "admin"},
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}

		token, err := GenerateEncryptedJWT(complexData, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestParseEncryptedJWT(t *testing.T) {
	setupTest(t)

	t.Run("successful encrypted token parsing", func(t *testing.T) {
		originalData := TestData{
			Name: "John Doe",
			Age:  30,
			ID:   "user-123",
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "test-issuer",
		}

		// Generate encrypted token
		token, err := GenerateEncryptedJWT(originalData, claims)
		require.NoError(t, err)

		// Parse the encrypted token
		var parsedData TestData
		err = ParseEncryptedJWT(token, &parsedData)
		require.NoError(t, err)
		assert.Equal(t, originalData, parsedData)
	})

	t.Run("parse into wrong type", func(t *testing.T) {
		originalData := TestData{
			Name: "John Doe",
			Age:  30,
			ID:   "user-123",
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}

		token, err := GenerateEncryptedJWT(originalData, claims)
		require.NoError(t, err)

		// Try to parse into wrong type
		var wrongType string
		err = ParseEncryptedJWT(token, &wrongType)
		assert.Error(t, err)
	})

	t.Run("invalid encrypted token", func(t *testing.T) {
		var data TestData
		err := ParseEncryptedJWT("invalid.token.string", &data)
		assert.Error(t, err)
	})

	t.Run("corrupted base64 data", func(t *testing.T) {
		// Create a valid token structure but with corrupted base64 data
		corruptedClaims := ValueClaim{
			Value: "not-valid-base64!@#$%",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token, err := GenerateJWT(corruptedClaims)
		require.NoError(t, err)

		var data TestData
		err = ParseEncryptedJWT(token, &data)
		assert.Error(t, err)
	})
}

func TestJWTRoundTrip(t *testing.T) {
	setupTest(t)

	t.Run("simple value round trip", func(t *testing.T) {
		originalClaims := ValueClaim{
			Value: "test-secret-data",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "test-service",
				Subject:   "user-123",
			},
		}

		// Generate → Parse round trip
		token, err := GenerateJWT(originalClaims)
		require.NoError(t, err)

		parsedClaims, err := ParseJWT(token)
		require.NoError(t, err)

		assert.Equal(t, originalClaims.Value, parsedClaims.Value)
		assert.Equal(t, originalClaims.Issuer, parsedClaims.Issuer)
		assert.Equal(t, originalClaims.Subject, parsedClaims.Subject)
	})

	t.Run("encrypted value round trip", func(t *testing.T) {
		originalData := TestData{
			Name: "Alice Smith",
			Age:  28,
			ID:   "user-456",
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "test-service",
			Subject:   "encryption-test",
		}

		// Generate → Parse round trip
		token, err := GenerateEncryptedJWT(originalData, claims)
		require.NoError(t, err)

		var parsedData TestData
		err = ParseEncryptedJWT(token, &parsedData)
		require.NoError(t, err)

		assert.Equal(t, originalData, parsedData)
	})

	t.Run("multiple round trips with same data", func(t *testing.T) {
		testData := TestData{
			Name: "Bob Johnson",
			Age:  35,
			ID:   "user-789",
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}

		// Multiple round trips should produce the same result
		for i := 0; i < 5; i++ {
			token, err := GenerateEncryptedJWT(testData, claims)
			require.NoError(t, err)

			var parsedData TestData
			err = ParseEncryptedJWT(token, &parsedData)
			require.NoError(t, err)

			assert.Equal(t, testData, parsedData)
		}
	})
}

func TestJWTEdgeCases(t *testing.T) {
	setupTest(t)

	t.Run("very large data", func(t *testing.T) {
		// Create a large data structure
		largeData := make(map[string]string)
		for i := 0; i < 1000; i++ {
			largeData[string(rune('a'+i%26))+string(rune('A'+i%26))] = "large data value " + string(rune(i))
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}

		token, err := GenerateEncryptedJWT(largeData, claims)
		require.NoError(t, err)

		var parsedData map[string]string
		err = ParseEncryptedJWT(token, &parsedData)
		require.NoError(t, err)

		assert.Equal(t, len(largeData), len(parsedData))
	})

	t.Run("empty string value", func(t *testing.T) {
		claims := ValueClaim{
			Value: "",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token, err := GenerateJWT(claims)
		require.NoError(t, err)

		parsedClaims, err := ParseJWT(token)
		require.NoError(t, err)
		assert.Equal(t, "", parsedClaims.Value)
	})

	t.Run("unicode data", func(t *testing.T) {
		unicodeData := TestData{
			Name: "测试用户 🚀",
			Age:  25,
			ID:   "用户-123-🎉",
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}

		token, err := GenerateEncryptedJWT(unicodeData, claims)
		require.NoError(t, err)

		var parsedData TestData
		err = ParseEncryptedJWT(token, &parsedData)
		require.NoError(t, err)

		assert.Equal(t, unicodeData, parsedData)
	})
}

// Benchmark tests
func BenchmarkGenerateJWT(b *testing.B) {
	setupTest(nil)
	claims := ValueClaim{
		Value: "benchmark-test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateJWT(claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseJWT(b *testing.B) {
	setupTest(nil)
	claims := ValueClaim{
		Value: "benchmark-test-value",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token, err := GenerateJWT(claims)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseJWT(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateEncryptedJWT(b *testing.B) {
	setupTest(nil)
	testData := TestData{
		Name: "Benchmark User",
		Age:  30,
		ID:   "bench-123",
	}
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateEncryptedJWT(testData, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseEncryptedJWT(b *testing.B) {
	setupTest(nil)
	testData := TestData{
		Name: "Benchmark User",
		Age:  30,
		ID:   "bench-123",
	}
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	token, err := GenerateEncryptedJWT(testData, claims)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var data TestData
		err := ParseEncryptedJWT(token, &data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

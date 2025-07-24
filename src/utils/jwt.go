package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cespare/go-smaz"
	"github.com/golang-jwt/jwt/v5"
)

// ValueClaim represents custom JWT claims structure containing a value string
// and standard JWT registered claims like expiration time, issuer, etc.
type ValueClaim struct {
	Value string `json:"value"` // Custom value field to store data in the JWT
	jwt.RegisteredClaims
}

// GenerateJWT creates and signs a JWT token using the provided ValueClaim
// Parameters:
//   - claims: ValueClaim struct containing the value and standard JWT claims
//
// Returns:
//   - string: Signed JWT token string
//   - error: Any error that occurred during token generation
func GenerateJWT(claims ValueClaim) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(cluster_secret_key[:])
}

// ParseJWT parses and validates a JWT token string, extracting the ValueClaim
// Parameters:
//   - tokenString: The JWT token string to parse and validate
//
// Returns:
//   - *ValueClaim: Pointer to the extracted ValueClaim if validation succeeds
//   - error: Any error that occurred during parsing or validation
func ParseJWT(tokenString string) (*ValueClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ValueClaim{}, func(token *jwt.Token) (any, error) {
		return cluster_secret_key[:], nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*ValueClaim); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// GenerateEncryptedJWT creates a JWT token with encrypted and compressed payload
// This function performs the following operations:
// 1. Marshals the value to JSON
// 2. Compresses the JSON using SMAZ compression
// 3. Encrypts the compressed data
// 4. Encodes the encrypted data to base64
// 5. Creates a JWT with the base64 string as the value
// Parameters:
//   - value: Any interface{} that can be JSON marshaled
//   - claims: Standard JWT registered claims (expiration, issuer, etc.)
//
// Returns:
//   - string: Signed JWT token containing encrypted data
//   - error: Any error that occurred during the encryption/JWT generation process
func GenerateEncryptedJWT(value interface{}, claims jwt.RegisteredClaims) (string, error) {
	json, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	compressed := smaz.Compress(json)
	encrypted, err := Encrypt(compressed, cluster_secret_key)
	if err != nil {
		return "", err
	}
	base64Value := base64.URLEncoding.EncodeToString(encrypted)
	encryptedValueClaim := ValueClaim{
		Value:            base64Value,
		RegisteredClaims: claims,
	}
	return GenerateJWT(encryptedValueClaim)
}

// ParseEncryptedJWT parses an encrypted JWT token and decrypts its payload
// This function performs the reverse operations of GenerateEncryptedJWT:
// 1. Parses the JWT token to extract the base64-encoded value
// 2. Decodes the base64 string to get encrypted data
// 3. Decrypts the data using the cluster secret key
// 4. Decompresses the decrypted data using SMAZ
// 5. Unmarshals the JSON into the provided interface
// Parameters:
//   - encryptedToken: The encrypted JWT token string to parse
//   - v: Pointer to the variable where the decrypted data should be unmarshaled
//
// Returns:
//   - error: Any error that occurred during parsing, decryption, or unmarshaling
func ParseEncryptedJWT(encryptedToken string, v any) error {
	claims, err := ParseJWT(encryptedToken)
	if err != nil {
		return err
	}
	base64Value := (claims.Value)
	decoded, err := base64.URLEncoding.DecodeString(base64Value)
	if err != nil {
		return err
	}
	decrypted, err := Decrypt(decoded, cluster_secret_key)
	if err != nil {
		return err
	}
	decompressed, err := smaz.Decompress(decrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(decompressed, v)
}

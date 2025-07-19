package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cespare/go-smaz"
	"github.com/golang-jwt/jwt/v5"
)

type ValueClaim struct {
	Value string `json:"value"`
	jwt.RegisteredClaims
}

func GenerateJWT(claims ValueClaim) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(cluster_secret_key[:])
}

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
	decompressed, err := smaz.Decompress(decoded)
	if err != nil {
		return err
	}
	decrypted, err := Decrypt(decompressed, cluster_secret_key)
	if err != nil {
		return err
	}
	return json.Unmarshal(decrypted, v)
}

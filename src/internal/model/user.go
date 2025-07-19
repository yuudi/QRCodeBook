package model

import (
	"crypto/subtle"
	"encoding/hex"
	"time"
	"yuudi/qrcodebook/src/utils"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/datatypes"
)

type User struct {
	ID           datatypes.BinUUID `gorm:"primaryKey" json:"id"`
	Username     string            `gorm:"uniqueIndex;size:32" json:"username"`
	Email        string            `gorm:"uniqueIndex;size:64" json:"email"`
	DisplayName  string            `gorm:"size:64" json:"display_name"`
	Credentials  []Credential      `gorm:"foreignKey:UserID" json:"credentials"`
	Salt         []byte            `gorm:"size:32" json:"-"`
	PasswordHash []byte            `gorm:"size:32" json:"-"`
}

func (u User) GetSaltHex() string {
	return hex.EncodeToString(u.Salt)
}

func (u User) CheckPasswordHash(hashHex string) bool {
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	if len(hashBytes) != len(u.PasswordHash) {
		return false
	}
	return subtle.ConstantTimeCompare(u.PasswordHash, hashBytes) == 1
}

type UserJWTContent struct {
	ID string `json:"id"`
}

func (u User) GetJWTToken() (string, error) {
	jwtContent := UserJWTContent{
		ID: u.ID.String(),
	}
	jwtToken, err := utils.GenerateEncryptedJWT(jwtContent, jwt.RegisteredClaims{
		Subject:   u.ID.String(),
		Issuer:    "qrcodebook",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
	})
	if err != nil {
		return "", err
	}
	return jwtToken, nil
}

func ParseUserFromJWT(tokenString string) (*UserJWTContent, error) {
	var jwtContent UserJWTContent
	err := utils.ParseEncryptedJWT(tokenString, &jwtContent)
	if err != nil {
		return nil, err
	}
	return &jwtContent, nil
}

func (u User) GetFullUser() (*User, error) {
	var user User
	result := DB.First(&user, "id = ?", u.ID)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

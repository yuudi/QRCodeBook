package model

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/datatypes"
)

type Credential struct {
	ID                     []byte            `gorm:"primaryKey" json:"id"`
	UserID                 datatypes.BinUUID `gorm:"index" json:"user_id"`
	WebauthnCredentialJson datatypes.JSONType[webauthn.Credential]
}

// WebAuthn User interface implementations
func (u User) WebAuthnID() []byte {
	return u.ID.Bytes()
}

func (u User) WebAuthnName() string {
	return u.Username
}

func (u User) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, len(u.Credentials))
	for i, cred := range u.Credentials {
		credentials[i] = cred.WebauthnCredentialJson.Data()
	}
	return credentials
}

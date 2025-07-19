package utils

import (
	"log"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var WebAuthn *webauthn.WebAuthn

func InitWebAuthn() {
	wconfig := &webauthn.Config{
		RPDisplayName: MustGetEnv("WEBAUTHN_RP_NAME"),                     // Display Name for your site
		RPID:          MustGetEnv("WEBAUTHN_RPID"),                        // Generally the FQDN for your site
		RPOrigins:     strings.Split(MustGetEnv("WEBAUTHN_ORIGINS"), ","), // The origin URLs for WebAuthn requests

		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    5 * time.Minute,
				TimeoutUVD: 5 * time.Minute,
			},
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    5 * time.Minute,
				TimeoutUVD: 5 * time.Minute,
			},
		},
	}

	var err error
	WebAuthn, err = webauthn.New(wconfig)
	if err != nil {
		log.Fatalf("Failed to create WebAuthn instance: %v", err)
	}
}

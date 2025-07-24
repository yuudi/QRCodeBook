package utils

import (
	"log"
	"time"
	"yuudi/qrcodebook/src/config"

	"github.com/go-webauthn/webauthn/webauthn"
)

var WebAuthn *webauthn.WebAuthn

func InitWebAuthn() {
	wconfig := &webauthn.Config{
		RPDisplayName: config.AppConfig.WebAuthn.RPName,  // Display Name for your site
		RPID:          config.AppConfig.WebAuthn.RPID,    // Generally the FQDN for your site
		RPOrigins:     config.AppConfig.WebAuthn.Origins, // The origin URLs for WebAuthn requests

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

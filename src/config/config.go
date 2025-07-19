package config

func Init() {
	InitJWT()
	InitDB()
	InitWebAuthn()
}

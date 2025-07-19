package config

import (
	"yuudi/qrcodebook/src/internal/model"
	"yuudi/qrcodebook/src/utils"
)

func Init() {
	utils.InitKey()
	utils.InitWebAuthn()
	model.InitDB()
}

package src

import (
	"log"
	"strconv"
	"yuudi/qrcodebook/src/config"
	"yuudi/qrcodebook/src/internal/model"
	"yuudi/qrcodebook/src/internal/router"
	"yuudi/qrcodebook/src/utils"

	"github.com/gin-gonic/gin"
)

func Run() {

	// Initialize all configurations
	config.Init()
	utils.InitKey()
	utils.InitWebAuthn()
	model.InitDB()

	if config.AppConfig.Mode == "production" {
		log.Println("Running in production mode")
		gin.SetMode(gin.ReleaseMode)
	} else {
		log.Println("Running in development mode")
	}

	r := router.SetupRouter()
	port := strconv.Itoa(config.AppConfig.Port)
	r.Run(":" + port)
}

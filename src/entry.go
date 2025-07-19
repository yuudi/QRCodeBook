package src

import (
	"log"
	"yuudi/qrcodebook/src/config"
	"yuudi/qrcodebook/src/internal/router"
	"yuudi/qrcodebook/src/utils"

	"github.com/gin-gonic/gin"
)

func Run() {
	if err := utils.LoadEnvFromFile(".env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Initialize all configurations
	config.Init()

	if utils.GetEnv("MODE") == "production" {
		log.Println("Running in production mode")
		gin.SetMode(gin.ReleaseMode)
	} else {
		log.Println("Running in development mode")
	}

	r := router.SetupRouter()
	port := utils.MustGetEnv("PORT")
	r.Run(":" + port)
}

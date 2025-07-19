package src

import (
	"log"
	"yuudi/qrcodebook/src/config"
	"yuudi/qrcodebook/src/internal/router"

	"github.com/gin-gonic/gin"
)

func Run() {
	if err := config.LoadEnvFromFile(".env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Initialize all configurations
	config.Init()

	if config.GetEnv("MODE") == "production" {
		log.Println("Running in production mode")
		gin.SetMode(gin.ReleaseMode)
	} else {
		log.Println("Running in development mode")
	}

	r := router.SetupRouter()
	port := config.MustGetEnv("PORT")
	r.Run(":" + port)
}

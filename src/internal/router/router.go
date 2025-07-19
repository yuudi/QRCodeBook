package router

import (
	_ "embed" // for embedding static files
	"yuudi/qrcodebook/src/internal/controller"

	"github.com/gin-gonic/gin"
)

//go:embed index.html
var staticIndexHTMLString string

func indexHTML(c *gin.Context) {
	c.String(200, staticIndexHTMLString)
}

func SetupRouter() *gin.Engine {
	r := gin.Default()

	// static files
	r.GET("/", indexHTML)
	r.GET("/index.html", indexHTML)

	// API routes
	api := r.Group("/api/v0")

	// Ping route
	api.GET("/ping", controller.Ping)

	// WebAuthn routes
	auth := api.Group("/auth")
	auth.POST("/register/begin", controller.RegisterBegin)
	auth.POST("/register/finish", controller.RegisterFinish)
	auth.POST("/login/begin", controller.LoginBegin)
	auth.POST("/login/finish", controller.LoginFinish)
	auth.POST("/logout", controller.Logout)

	return r
}

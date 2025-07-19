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

	// User Auth routes
	auth := api.Group("/auth")
	auth.POST("/salts", controller.GetNewSalt)
	auth.POST("/register", controller.RegisterUser)
	auth.POST("/login", controller.LoginUser)
	auth.GET("/salts/:username", controller.GetUserSalt) // Does not require auth, so outside of user group

	// WebAuthn routes
	webauthn := api.Group("/webauthn")
	webauthn.POST("/register/begin", controller.RegisterBegin)
	webauthn.POST("/register/finish", controller.RegisterFinish)
	webauthn.POST("/login/begin", controller.LoginBegin)
	webauthn.POST("/login/finish", controller.LoginFinish)

	api.POST("/logout", controller.Logout)

	// User self routes
	me := api.Group("/me")
	me.Use(controller.LoginRequired())

	return r
}

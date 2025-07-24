package router

import (
	_ "embed" // for embedding static files
	"yuudi/qrcodebook/src/internal/controller"
	"yuudi/qrcodebook/src/internal/middleware"

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
	me.Use(middleware.LoginRequired())

	// Notes routes
	notes := api.Group("/notes")
	notes.Use(middleware.LoginRequired())
	{
		notes.GET("", controller.GetUserNotes)
		notes.GET("/basic", controller.GetUserNotesBasic)
		notes.GET("/stats", controller.GetUserStats)
		notes.GET("/:note_id", controller.GetNoteContent)
		notes.GET("/:note_id/versions", controller.GetNoteVersions)
		notes.GET("/:note_id/versions/:version_no", controller.GetNoteVersionContent)
		notes.POST("", controller.CreateNote)
		notes.POST("/:note_id/versions", controller.CreateNoteVersion)
		notes.DELETE("/:note_id", controller.DeleteNote)
	}

	return r
}

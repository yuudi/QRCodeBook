package middleware

import (
	"net/http"
	"yuudi/qrcodebook/src/internal/model"
	"yuudi/qrcodebook/src/utils"

	"github.com/gin-gonic/gin"
)

func LoginRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("user_session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		var jwtContent model.UserJWTContent

		err = utils.ParseEncryptedJWT(token, &jwtContent)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user", jwtContent)
		c.Next()
	}
}

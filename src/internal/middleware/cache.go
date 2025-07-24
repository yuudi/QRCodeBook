package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
)

func PublicCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Modern browsers and proxies
		c.Header("Cache-Control", "public, max-age=3600")
		// HTTP/1.0 compatibility
		c.Header("Expires", time.Now().Add(time.Hour).UTC().Format(time.RFC1123))
		c.Next()
	}
}

func PrivateCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Modern browsers only
		c.Header("Cache-Control", "private, max-age=3600")
		// HTTP/1.0 compatibility
		c.Header("Expires", time.Now().Add(time.Hour).UTC().Format(time.RFC1123))
		c.Next()
	}
}

func NoCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Comprehensive no-cache headers for maximum compatibility
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")                       // HTTP/1.0 compatibility
		c.Header("Expires", "Thu, 01 Jan 1970 00:00:00 GMT") // HTTP/1.0 compatibility
		c.Next()
	}
}

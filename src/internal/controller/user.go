package controller

import (
	"net/http"
	"yuudi/qrcodebook/src/config"
	"yuudi/qrcodebook/src/internal/model"

	"github.com/gin-gonic/gin"
)

func GetUsers(c *gin.Context) {
	var users []model.User
	result := config.DB.Find(&users)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func Hello(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Hello, Gin!"})
}

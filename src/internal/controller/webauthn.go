package controller

import (
	"net/http"
	"yuudi/qrcodebook/src/config"
	"yuudi/qrcodebook/src/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RegisterSessionData struct {
	ID                  datatypes.BinUUID    `json:"id"`
	Username            string               `json:"username"`
	Email               string               `json:"email"`
	WebauthnSessionData webauthn.SessionData `json:"webauthn_session_data"`
}

// RegisterBegin Begin webauthn registration process
func RegisterBegin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check length of username and email
	if len(req.Username) > 32 || len(req.Email) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username or email too long"})
		return
	}

	// Check if user already exists
	var existingUser model.User
	err := config.DB.First(&existingUser, "username = ? OR email = ?", req.Username, req.Email).Error
	if err == nil {
		if existingUser.Username == req.Username {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		} else {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		}
		return
	}
	if err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing user: " + err.Error()})
		return
	}

	// Create a new temporary user object
	user := model.User{
		ID:       datatypes.NewBinUUIDv4(),
		Username: req.Username,
		Email:    req.Email,
	}

	// generate webauthn registration options
	options, sessionData, err := config.WebAuthn.BeginRegistration(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate registration options: " + err.Error()})
		return
	}

	// Generate JWT token for the session
	encryptedJWT, err := config.GenerateEncryptedJWT(RegisterSessionData{
		Username:            req.Username,
		Email:               req.Email,
		WebauthnSessionData: *sessionData,
	}, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(sessionData.Expires),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT: " + err.Error()})
		return
	}

	// Set session cookie
	c.SetCookie("webauthn_registration_session", encryptedJWT, 600, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"options": options,
	})
}

// RegisterFinish finish webauthn registration process
func RegisterFinish(c *gin.Context) {
	// Get session ID
	encryptedJWT, err := c.Cookie("webauthn_registration_session")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session not found"})
		return
	}

	// Get session data
	sessionData := RegisterSessionData{}
	if err := config.ParseEncryptedJWT(encryptedJWT, &sessionData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session: " + err.Error()})
		return
	}

	// Create a new user object
	user := model.User{
		ID:       sessionData.ID,
		Username: sessionData.Username,
		Email:    sessionData.Email,
	}

	// Finish registration
	credential, err := config.WebAuthn.FinishRegistration(&user, sessionData.WebauthnSessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Registration verification failed: " + err.Error()})
		return
	}

	// Start database transaction
	tx := config.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Save user to database
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user: " + err.Error()})
		return
	}

	// Save credential to database
	cred := model.Credential{
		UserID:                 user.ID,
		ID:                     credential.ID,
		WebauthnCredentialJson: datatypes.NewJSONType(*credential),
	}

	if err := tx.Create(&cred).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save credential: " + err.Error()})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction: " + err.Error()})
		return
	}

	// Clear session
	c.SetCookie("webauthn_session", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Registration successful",
		"user":    user,
	})
}

// LoginBegin Start login process
func LoginBegin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// find user
	var user model.User
	if err := config.DB.Preload("Credentials").Where("username = ?", req.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user: " + err.Error()})
		}
		return
	}

	// Generate login options
	options, sessionData, err := config.WebAuthn.BeginLogin(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate login options: " + err.Error()})
		return
	}

	// Store session data
	encryptedJWT, err := config.GenerateEncryptedJWT(sessionData, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(sessionData.Expires),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT: " + err.Error()})
		return
	}

	// Set session cookie
	c.SetCookie("webauthn_login_session", encryptedJWT, 600, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"options": options,
	})
}

// LoginFinish Finish login process
func LoginFinish(c *gin.Context) {
	// Get session ID
	encryptedJWT, err := c.Cookie("webauthn_login_session")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session not found"})
		return
	}

	// Get session data
	sessionData := webauthn.SessionData{}
	if err := config.ParseEncryptedJWT(encryptedJWT, &sessionData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session expired"})
		return
	}

	// Find user
	var user model.User
	if err := config.DB.Preload("Credentials").First(&user, sessionData.UserID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user: " + err.Error()})
		return
	}

	// Finish login
	credential, err := config.WebAuthn.FinishLogin(&user, sessionData, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "登录验证失败: " + err.Error()})
		return
	}

	// Update sign count in the database
	var dbCred model.Credential
	if err := config.DB.Where("id = ?", string(credential.ID)).First(&dbCred).Error; err == nil {
		dbCred.WebauthnCredentialJson = datatypes.NewJSONType(*credential)
		config.DB.Save(&dbCred)
	}

	// Clear session
	c.SetCookie("webauthn_login_session", "", -1, "/", "", false, true)

	// TODO: create user JWT token

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user":    user,
	})
}

// Logout
func Logout(c *gin.Context) {
	c.SetCookie("user_session", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

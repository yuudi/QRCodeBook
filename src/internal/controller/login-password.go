package controller

import (
	"encoding/hex"
	"net/http"
	"time"
	"yuudi/qrcodebook/src/internal/model"
	"yuudi/qrcodebook/src/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func GetNewSalt(c *gin.Context) {
	salt, err := utils.GenerateCryptoRandomBytes(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	saltHex := hex.EncodeToString(salt)
	token, err := utils.GenerateJWT(utils.ValueClaim{Value: saltHex, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.SetCookie("salt_token", token, 600, "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{"salt": saltHex})
}

func GetUserSalt(c *gin.Context) {
	username := c.Param("username")
	if len(username) == 0 || len(username) > 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username"})
		return
	}
	var user model.User
	result := model.DB.First(&user, "username = ?", username)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"salt": user.GetSaltHex()})
}

type UserRegisterRequest struct {
	Username     string `json:"username" binding:"required"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Salt         string `json:"salt" binding:"required"`
	PasswordHash string `json:"password_hash" binding:"required"`
}

func RegisterUser(c *gin.Context) {
	var req UserRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate input lengths
	if len(req.Username) == 0 || len(req.Username) > 32 ||
		(len(req.Email) > 0 && len(req.Email) > 64) ||
		(len(req.DisplayName) > 0 && len(req.DisplayName) > 64) ||
		len(req.Salt) != 64 || len(req.PasswordHash) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input lengths"})
		return
	}

	// Check if username or email already exists
	var existingUser model.User
	err := model.DB.First(&existingUser, "username = ? OR email = ?", req.Username, req.Email).Error
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

	// Validate Salt JWT
	saltToken, err := c.Cookie("salt_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Salt token not found"})
		return
	}
	claims, err := utils.ParseJWT(saltToken)
	if err != nil || claims.Value != req.Salt {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid salt token"})
		return
	}

	saltBytes, err := hex.DecodeString(req.Salt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid salt format"})
		return
	}
	passwordHashBytes, err := hex.DecodeString(req.PasswordHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password hash format"})
		return
	}

	// Create new user
	user := model.User{
		ID:           datatypes.NewBinUUIDv4(),
		Username:     req.Username,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		Salt:         saltBytes,
		PasswordHash: passwordHashBytes,
	}

	result := model.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}

	// Generate user JWT token and set cookie
	token, err := user.GetJWTToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate user token: " + err.Error()})
		return
	}
	c.SetCookie("user_session", token, 30*24*3600, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully", "user_id": user.ID})
}

type UserLoginRequest struct {
	Username     string `json:"username" binding:"required"`
	PasswordHash string `json:"password_hash" binding:"required"`
}

func LoginUser(c *gin.Context) {
	var req UserLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate input lengths
	if len(req.Username) == 0 || len(req.Username) > 32 || len(req.PasswordHash) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input lengths"})
		return
	}

	// Find user by username
	var user model.User
	result := model.DB.First(&user, "username = ?", req.Username)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}

	// Check password hash
	if !user.CheckPasswordHash(req.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Generate user JWT token and set cookie
	token, err := user.GetJWTToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate user token: " + err.Error()})
		return
	}
	c.SetCookie("user_session", token, 30*24*3600, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user_id": user.ID})
}

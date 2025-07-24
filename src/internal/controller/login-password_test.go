package controller

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"yuudi/qrcodebook/src/internal/model"
	"yuudi/qrcodebook/src/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate the tables
	err = db.AutoMigrate(&model.User{}, &model.Credential{})
	require.NoError(t, err)

	return db
}

// setupTestRouter creates a Gin router for testing
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	return router
}

// setupTestUser creates a test user in the database
func setupTestUser(t *testing.T, db *gorm.DB) model.User {
	salt, err := utils.GenerateCryptoRandomBytes(32)
	require.NoError(t, err)

	passwordHash, err := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	require.NoError(t, err)

	user := model.User{
		ID:           datatypes.NewBinUUIDv4(),
		Username:     "testuser",
		Email:        "test@example.com",
		DisplayName:  "Test User",
		Salt:         salt,
		PasswordHash: passwordHash,
	}

	result := db.Create(&user)
	require.NoError(t, result.Error)

	return user
}

// setupTestUserWithName creates a test user with a specific name in the database
func setupTestUserWithName(t *testing.T, db *gorm.DB, username, email string) model.User {
	salt, err := utils.GenerateCryptoRandomBytes(32)
	require.NoError(t, err)

	passwordHash, err := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	require.NoError(t, err)

	user := model.User{
		ID:           datatypes.NewBinUUIDv4(),
		Username:     username,
		Email:        email,
		DisplayName:  "Test User",
		Salt:         salt,
		PasswordHash: passwordHash,
	}

	result := db.Create(&user)
	require.NoError(t, result.Error)

	return user
}

// setupControllerTest initializes the test environment
func setupControllerTest(t *testing.T) (*gin.Engine, *gorm.DB, func()) {
	// Setup crypto utils with a test key
	cluster_secret_key := [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	// Set the utils key directly for testing
	utils.SetTestKey(cluster_secret_key)

	// Setup test database
	db := setupTestDB(t)
	originalDB := model.DB
	model.DB = db

	// Setup router
	router := setupTestRouter()

	// Cleanup function
	cleanup := func() {
		model.DB = originalDB
	}

	return router, db, cleanup
}

func TestGetNewSalt(t *testing.T) {
	router, _, cleanup := setupControllerTest(t)
	defer cleanup()

	router.GET("/salt/new", GetNewSalt)

	t.Run("successful salt generation", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/salt/new", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		salt, exists := response["salt"]
		assert.True(t, exists)
		assert.Len(t, salt, 64) // 32 bytes in hex = 64 characters

		// Check if salt is valid hex
		_, err = hex.DecodeString(salt)
		assert.NoError(t, err)

		// Check if cookie is set
		cookies := w.Result().Cookies()
		var saltCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "salt_token" {
				saltCookie = cookie
				break
			}
		}
		assert.NotNil(t, saltCookie)
		assert.Equal(t, 600, saltCookie.MaxAge)
		assert.True(t, saltCookie.HttpOnly)
		assert.True(t, saltCookie.Secure)

		// Verify JWT token contains the salt
		claims, err := utils.ParseJWT(saltCookie.Value)
		require.NoError(t, err)
		assert.Equal(t, salt, claims.Value)
	})
}

func TestGetUserSalt(t *testing.T) {
	router, db, cleanup := setupControllerTest(t)
	defer cleanup()

	user := setupTestUser(t, db)
	router.GET("/salt/:username", GetUserSalt)

	t.Run("successful salt retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/salt/"+user.Username, nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		salt, exists := response["salt"]
		assert.True(t, exists)
		assert.Equal(t, user.GetSaltHex(), salt)
	})

	t.Run("user not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/salt/nonexistentuser", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "User not found", response["error"])
	})

	t.Run("invalid username - empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		// For empty username, we need to test the actual path parameter behavior
		// Since the path parameter would be empty, this would result in different routing
		req, _ := http.NewRequest("GET", "/salt/", nil)
		router.ServeHTTP(w, req)

		// This will be 404 because the route doesn't match /salt/ but /salt/:username
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid username - too long", func(t *testing.T) {
		longUsername := string(make([]byte, 33))
		for i := range longUsername {
			longUsername = longUsername[:i] + "a" + longUsername[i+1:]
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/salt/"+longUsername, nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid username", response["error"])
	})
}

func TestRegisterUser(t *testing.T) {
	router, db, cleanup := setupControllerTest(t)
	defer cleanup()

	router.POST("/register", RegisterUser)

	// Helper function to create a valid salt token
	createSaltToken := func() (string, string) {
		salt, _ := utils.GenerateCryptoRandomBytes(32)
		saltHex := hex.EncodeToString(salt)
		token, _ := utils.GenerateJWT(utils.ValueClaim{
			Value: saltHex,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
		})
		return saltHex, token
	}

	t.Run("successful registration", func(t *testing.T) {
		saltHex, saltToken := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     "newuser",
			Email:        "newuser@example.com",
			DisplayName:  "New User",
			Salt:         saltHex,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: saltToken})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "User registered successfully", response["message"])
		assert.NotNil(t, response["user_id"])

		// Check if user is created in database
		var user model.User
		result := db.First(&user, "username = ?", reqBody.Username)
		assert.NoError(t, result.Error)
		assert.Equal(t, reqBody.Username, user.Username)
		assert.Equal(t, reqBody.Email, user.Email)
		assert.Equal(t, reqBody.DisplayName, user.DisplayName)

		// Check if session cookie is set
		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "user_session" {
				sessionCookie = cookie
				break
			}
		}
		assert.NotNil(t, sessionCookie)
		assert.True(t, sessionCookie.HttpOnly)
		assert.True(t, sessionCookie.Secure)
	})

	t.Run("missing required fields", func(t *testing.T) {
		reqBody := UserRegisterRequest{
			Email: "incomplete@example.com",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid input lengths", func(t *testing.T) {
		saltHex, saltToken := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     string(make([]byte, 33)), // Too long
			Email:        "test@example.com",
			DisplayName:  "Test User",
			Salt:         saltHex,
			PasswordHash: "short", // Too short
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: saltToken})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid input lengths", response["error"])
	})

	t.Run("username already exists", func(t *testing.T) {
		existingUser := setupTestUserWithName(t, db, "existinguser1", "existing1@example.com")
		saltHex, saltToken := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     existingUser.Username,
			Email:        "different@example.com",
			DisplayName:  "Different User",
			Salt:         saltHex,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: saltToken})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Username already exists", response["error"])
	})

	t.Run("email already exists", func(t *testing.T) {
		// Create a user for this specific test
		existingUser := setupTestUserWithName(t, db, "existinguser2", "existing2@example.com")
		saltHex, saltToken := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     "differentuser",
			Email:        existingUser.Email,
			DisplayName:  "Different User",
			Salt:         saltHex,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: saltToken})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Email already exists", response["error"])
	})

	t.Run("missing salt token", func(t *testing.T) {
		saltHex, _ := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     "notoken",
			Email:        "notoken@example.com",
			DisplayName:  "No Token User",
			Salt:         saltHex,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Salt token not found", response["error"])
	})

	t.Run("invalid salt token", func(t *testing.T) {
		saltHex, _ := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     "invalidtoken",
			Email:        "invalidtoken@example.com",
			DisplayName:  "Invalid Token User",
			Salt:         saltHex,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: "invalid.token.here"})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid salt token", response["error"])
	})

	t.Run("salt mismatch", func(t *testing.T) {
		_, saltToken := createSaltToken()
		differentSalt := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		reqBody := UserRegisterRequest{
			Username:     "saltmismatch",
			Email:        "saltmismatch@example.com",
			DisplayName:  "Salt Mismatch User",
			Salt:         differentSalt,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: saltToken})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid salt token", response["error"])
	})

	t.Run("invalid hex format", func(t *testing.T) {
		_, saltToken := createSaltToken()

		reqBody := UserRegisterRequest{
			Username:     "invalidhex",
			Email:        "invalidhex@example.com",
			DisplayName:  "Invalid Hex User",
			Salt:         "invalid_hex_string_that_is_not_valid_hex_format_here!!!!",
			PasswordHash: "not_valid_hex!",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "salt_token", Value: saltToken})

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestLoginUser(t *testing.T) {
	router, db, cleanup := setupControllerTest(t)
	defer cleanup()

	user := setupTestUser(t, db)
	router.POST("/login", LoginUser)

	t.Run("successful login", func(t *testing.T) {
		reqBody := UserLoginRequest{
			Username:     user.Username,
			PasswordHash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Login successful", response["message"])
		assert.NotNil(t, response["user_id"])

		// Check if session cookie is set
		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "user_session" {
				sessionCookie = cookie
				break
			}
		}
		assert.NotNil(t, sessionCookie)
		assert.True(t, sessionCookie.HttpOnly)
		assert.True(t, sessionCookie.Secure)
	})

	t.Run("missing required fields", func(t *testing.T) {
		reqBody := UserLoginRequest{
			Username: user.Username,
			// Missing password hash
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid input lengths", func(t *testing.T) {
		reqBody := UserLoginRequest{
			Username:     string(make([]byte, 33)), // Too long
			PasswordHash: "short",                  // Too short
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid input lengths", response["error"])
	})

	t.Run("user not found", func(t *testing.T) {
		reqBody := UserLoginRequest{
			Username:     "nonexistentuser",
			PasswordHash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid username or password", response["error"])
	})

	t.Run("wrong password", func(t *testing.T) {
		reqBody := UserLoginRequest{
			Username:     user.Username,
			PasswordHash: "0000000000000000000000000000000000000000000000000000000000000000",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid username or password", response["error"])
	})

	t.Run("empty username", func(t *testing.T) {
		reqBody := UserLoginRequest{
			Username:     "",
			PasswordHash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		}

		jsonBody, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// This will be caught by the binding validation, not the length validation
		assert.Contains(t, response["error"], "Username")
	})
}

// Integration tests for complete workflows
func TestUserRegistrationLoginFlow(t *testing.T) {
	router, db, cleanup := setupControllerTest(t)
	defer cleanup()

	router.GET("/salt/new", GetNewSalt)
	router.POST("/register", RegisterUser)
	router.POST("/login", LoginUser)

	t.Run("complete registration and login flow", func(t *testing.T) {
		// Step 1: Get new salt
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/salt/new", nil)
		router.ServeHTTP(w1, req1)

		assert.Equal(t, http.StatusOK, w1.Code)

		var saltResponse map[string]string
		err := json.Unmarshal(w1.Body.Bytes(), &saltResponse)
		require.NoError(t, err)

		salt := saltResponse["salt"]
		assert.Len(t, salt, 64)

		// Get salt cookie
		cookies := w1.Result().Cookies()
		var saltCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "salt_token" {
				saltCookie = cookie
				break
			}
		}
		require.NotNil(t, saltCookie)

		// Step 2: Register user
		registerReq := UserRegisterRequest{
			Username:     "flowuser",
			Email:        "flowuser@example.com",
			DisplayName:  "Flow User",
			Salt:         salt,
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody, _ := json.Marshal(registerReq)
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
		req2.Header.Set("Content-Type", "application/json")
		req2.AddCookie(saltCookie)

		router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)

		var registerResponse map[string]interface{}
		err = json.Unmarshal(w2.Body.Bytes(), &registerResponse)
		require.NoError(t, err)

		assert.Equal(t, "User registered successfully", registerResponse["message"])

		// Step 3: Login with the registered user
		loginReq := UserLoginRequest{
			Username:     "flowuser",
			PasswordHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		}

		jsonBody2, _ := json.Marshal(loginReq)
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody2))
		req3.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w3, req3)

		assert.Equal(t, http.StatusOK, w3.Code)

		var loginResponse map[string]interface{}
		err = json.Unmarshal(w3.Body.Bytes(), &loginResponse)
		require.NoError(t, err)

		assert.Equal(t, "Login successful", loginResponse["message"])

		// Verify user exists in database
		var user model.User
		result := db.First(&user, "username = ?", "flowuser")
		assert.NoError(t, result.Error)
		assert.Equal(t, "flowuser", user.Username)
		assert.Equal(t, "flowuser@example.com", user.Email)
		assert.Equal(t, "Flow User", user.DisplayName)
	})
}

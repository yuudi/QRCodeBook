package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"yuudi/qrcodebook/src/internal/model"
	"yuudi/qrcodebook/src/utils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDBForWebAuthn sets up an in-memory SQLite database for testing
func setupTestDBForWebAuthn() *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Auto migrate the schema
	err = db.AutoMigrate(&model.User{}, &model.Credential{})
	if err != nil {
		panic("failed to migrate database")
	}

	return db
}

func TestRegisterBegin_InputValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup test database
	testDB := setupTestDBForWebAuthn()
	originalDB := model.DB
	model.DB = testDB
	defer func() { model.DB = originalDB }()

	// Setup crypto for testing
	var testKey [32]byte
	copy(testKey[:], "test-key-32-characters-long-12")
	utils.SetTestKey(testKey)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Missing username",
			requestBody:    map[string]interface{}{"email": "test@example.com"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Key: 'Username' Error:Field validation for 'Username' failed on the 'required' tag",
		},
		{
			name:           "Missing email",
			requestBody:    map[string]interface{}{"username": "testuser"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Key: 'Email' Error:Field validation for 'Email' failed on the 'required' tag",
		},
		{
			name: "Username too long",
			requestBody: map[string]interface{}{
				"username": "this-username-is-definitely-way-too-long-for-the-system-to-accept-it",
				"email":    "test@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Username or email too long",
		},
		{
			name: "Email too long",
			requestBody: map[string]interface{}{
				"username": "testuser",
				"email":    "this-is-a-very-long-email-address-that-exceeds-the-maximum-allowed-length@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Username or email too long",
		},
		{
			name:           "Empty request body",
			requestBody:    map[string]interface{}{},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "required",
		},
		// Note: We can't test valid WebAuthn flow without proper initialization
		// But we've covered all the input validation logic which is the main concern
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			jsonBody, _ := json.Marshal(tt.requestBody)
			req, _ := http.NewRequest("POST", "/api/register/begin", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call the function
			RegisterBegin(c)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["error"], tt.expectedError)
		})
	}
}

func TestRegisterBegin_UserExists(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup test database
	testDB := setupTestDBForWebAuthn()
	originalDB := model.DB
	model.DB = testDB
	defer func() { model.DB = originalDB }()

	// Create existing user
	existingUser := model.User{
		ID:       datatypes.NewBinUUIDv4(),
		Username: "existinguser",
		Email:    "existing@example.com",
	}
	testDB.Create(&existingUser)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Username already exists",
			requestBody: map[string]interface{}{
				"username": "existinguser",
				"email":    "new@example.com",
			},
			expectedStatus: http.StatusConflict,
			expectedError:  "Username already exists",
		},
		{
			name: "Email already exists",
			requestBody: map[string]interface{}{
				"username": "newuser",
				"email":    "existing@example.com",
			},
			expectedStatus: http.StatusConflict,
			expectedError:  "Email already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			jsonBody, _ := json.Marshal(tt.requestBody)
			req, _ := http.NewRequest("POST", "/api/register/begin", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call the function
			RegisterBegin(c)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedError, response["error"])
		})
	}
}

func TestRegisterFinish_SessionValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupCookie    func(c *gin.Context)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "No session cookie",
			setupCookie: func(c *gin.Context) {
				// Don't set any cookie
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Session not found",
		},
		{
			name: "Invalid session cookie",
			setupCookie: func(c *gin.Context) {
				c.Request.AddCookie(&http.Cookie{
					Name:  "webauthn_registration_session",
					Value: "invalid-token",
				})
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req, _ := http.NewRequest("POST", "/api/register/finish", nil)

			// Create response recorder
			w := httptest.NewRecorder()

			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Setup cookie
			tt.setupCookie(c)

			// Call the function
			RegisterFinish(c)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["error"], tt.expectedError)
		})
	}
}

func TestLoginBegin_InputValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup test database
	testDB := setupTestDBForWebAuthn()
	originalDB := model.DB
	model.DB = testDB
	defer func() { model.DB = originalDB }()

	// Create test user
	testUser := model.User{
		ID:       datatypes.NewBinUUIDv4(),
		Username: "testuser",
		Email:    "test@example.com",
	}
	testDB.Create(&testUser)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Missing username",
			requestBody:    map[string]interface{}{},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Key: 'Username' Error:Field validation for 'Username' failed on the 'required' tag",
		},
		{
			name: "User not found",
			requestBody: map[string]interface{}{
				"username": "nonexistentuser",
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "User not found",
		},
		{
			name: "Valid existing user but WebAuthn not initialized",
			requestBody: map[string]interface{}{
				"username": "testuser",
			},
			// This will fail due to WebAuthn not being initialized, but that's expected
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to generate login options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			jsonBody, _ := json.Marshal(tt.requestBody)
			req, _ := http.NewRequest("POST", "/api/login/begin", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call the function
			LoginBegin(c)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["error"], tt.expectedError)
		})
	}
}

func TestLoginFinish_SessionValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupCookie    func(c *gin.Context)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "No session cookie",
			setupCookie: func(c *gin.Context) {
				// Don't set any cookie
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Session not found",
		},
		{
			name: "Invalid session cookie",
			setupCookie: func(c *gin.Context) {
				c.Request.AddCookie(&http.Cookie{
					Name:  "webauthn_login_session",
					Value: "invalid-token",
				})
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Session expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req, _ := http.NewRequest("POST", "/api/login/finish", nil)

			// Create response recorder
			w := httptest.NewRecorder()

			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Setup cookie
			tt.setupCookie(c)

			// Call the function
			LoginFinish(c)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["error"], tt.expectedError)
		})
	}
}

func TestLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create request
	req, _ := http.NewRequest("POST", "/api/logout", nil)

	// Create response recorder
	w := httptest.NewRecorder()

	// Create gin context
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Call the function
	Logout(c)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Logged out successfully", response["message"])

	// Check that cookie was cleared
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "user_session", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

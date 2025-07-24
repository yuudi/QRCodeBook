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
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupNoteTestDB creates an in-memory SQLite database for testing
func setupNoteTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate the tables
	err = db.AutoMigrate(&model.User{}, &model.Note{}, &model.NoteVersion{})
	require.NoError(t, err)

	return db
}

// setupNoteControllerTest initializes the test environment for note tests
func setupNoteControllerTest(t *testing.T) (*gin.Engine, *gorm.DB, func()) {
	// Setup crypto utils with a test key
	cluster_secret_key := [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	utils.SetTestKey(cluster_secret_key)

	// Setup test database
	db := setupNoteTestDB(t)
	originalDB := model.DB
	model.DB = db

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Cleanup function
	cleanup := func() {
		model.DB = originalDB
	}

	return router, db, cleanup
}

// createTestUser creates a test user in the database
func createTestUser(t *testing.T, db *gorm.DB, userID string) model.User {
	// Generate unique username using UUID
	uniqueUsername := datatypes.NewBinUUIDv4().String()
	uniqueEmail := uniqueUsername + "@example.com"

	user := model.User{
		ID:          datatypes.NewBinUUIDv4(),
		Username:    uniqueUsername,
		Email:       uniqueEmail,
		DisplayName: "Test User",
	}

	result := db.Create(&user)
	require.NoError(t, result.Error)

	return user
}

// createTestNote creates a test note with its first version
func createTestNote(t *testing.T, db *gorm.DB, noteID, userID string) (model.Note, model.NoteVersion) {
	note := model.Note{
		NoteID:          noteID,
		UserID:          userID,
		LatestVersionNo: 1,
	}

	result := db.Create(&note)
	require.NoError(t, result.Error)

	version := model.NoteVersion{
		NoteID:           noteID,
		VersionNo:        1,
		EncryptedTitle:   []byte("encrypted_title"),
		EncryptedContent: []byte("encrypted_content"),
	}

	result = db.Create(&version)
	require.NoError(t, result.Error)

	return note, version
}

// setUserContext sets user context in Gin context for testing
func setUserContext(c *gin.Context, userID string) {
	userJWT := model.UserJWTContent{
		ID: userID,
	}
	c.Set("user", userJWT)
}

func TestGetUserNotes(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	createTestNote(t, db, "note1", userID)
	createTestNote(t, db, "note2", userID)

	router.GET("/notes", func(c *gin.Context) {
		setUserContext(c, userID)
		GetUserNotes(c)
	})

	t.Run("successful retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response NoteListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, int64(2), response.Total)
		assert.Equal(t, 1, response.Page)
		assert.Equal(t, 20, response.PageSize)
		assert.Equal(t, 1, response.TotalPages)
		assert.Len(t, response.Notes, 2)
	})

	t.Run("with pagination", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes?page=1&page_size=1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response NoteListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, int64(2), response.Total)
		assert.Equal(t, 1, response.Page)
		assert.Equal(t, 1, response.PageSize)
		assert.Equal(t, 2, response.TotalPages)
		assert.Len(t, response.Notes, 1)
	})

	t.Run("unauthorized - no user context", func(t *testing.T) {
		router.GET("/notes_no_auth", GetUserNotes)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes_no_auth", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid user context", response["error"])
	})
}

func TestGetUserNotesBasic(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	createTestNote(t, db, "note1", userID)

	router.GET("/notes/basic", func(c *gin.Context) {
		setUserContext(c, userID)
		GetUserNotesBasic(c)
	})

	t.Run("successful retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/basic", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(1), response["total"])
		assert.Equal(t, float64(1), response["page"])
		assert.Equal(t, float64(50), response["page_size"])
		assert.Equal(t, float64(1), response["total_pages"])
	})
}

func TestGetNoteContent(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	noteID := "test-note-id"
	_, version := createTestNote(t, db, noteID, userID)

	router.GET("/notes/:note_id", func(c *gin.Context) {
		setUserContext(c, userID)
		GetNoteContent(c)
	})

	t.Run("successful retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/"+noteID, nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response model.NoteVersion
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, noteID, response.NoteID)
		assert.Equal(t, 1, response.VersionNo)
		assert.Equal(t, version.EncryptedTitle, response.EncryptedTitle)
	})

	t.Run("note not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/nonexistent", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Note not found", response["error"])
	})

	t.Run("missing note ID", func(t *testing.T) {
		router.GET("/notes/", func(c *gin.Context) {
			setUserContext(c, userID)
			GetNoteContent(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGetNoteVersionContent(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	noteID := "test-note-id"
	createTestNote(t, db, noteID, userID)

	router.GET("/notes/:note_id/versions/:version_no", func(c *gin.Context) {
		setUserContext(c, userID)
		GetNoteVersionContent(c)
	})

	t.Run("successful retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/"+noteID+"/versions/1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response model.NoteVersion
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, noteID, response.NoteID)
		assert.Equal(t, 1, response.VersionNo)
	})

	t.Run("invalid version number", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/"+noteID+"/versions/invalid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Invalid version number", response["error"])
	})

	t.Run("access denied - different user", func(t *testing.T) {
		otherUser := createTestUser(t, db, "")
		otherUserID := otherUser.ID.String()

		router.GET("/notes/:note_id/versions/:version_no/denied", func(c *gin.Context) {
			setUserContext(c, otherUserID)
			GetNoteVersionContent(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/"+noteID+"/versions/1/denied", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Access denied", response["error"])
	})
}

func TestGetNoteVersions(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	noteID := "test-note-id"
	createTestNote(t, db, noteID, userID)

	router.GET("/notes/:note_id/versions", func(c *gin.Context) {
		setUserContext(c, userID)
		GetNoteVersions(c)
	})

	t.Run("successful retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/"+noteID+"/versions", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response NoteVersionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, int64(1), response.Total)
		assert.Len(t, response.Versions, 1)
		assert.Equal(t, noteID, response.Versions[0].NoteID)
		assert.Equal(t, 1, response.Versions[0].VersionNo)
	})

	t.Run("note not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/notes/nonexistent/versions", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestCreateNote(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()

	router.POST("/notes", func(c *gin.Context) {
		setUserContext(c, userID)
		CreateNote(c)
	})

	t.Run("successful creation", func(t *testing.T) {
		req := CreateNoteRequest{
			NoteID:           "new-note-id",
			EncryptedTitle:   []byte("encrypted_title"),
			EncryptedContent: []byte("encrypted_content"),
		}

		jsonBody, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes", bytes.NewBuffer(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Note created successfully", response["message"])
		assert.Equal(t, "new-note-id", response["note_id"])

		// Verify note was created in database
		var note model.Note
		err = db.Where("note_id = ?", "new-note-id").First(&note).Error
		require.NoError(t, err)
		assert.Equal(t, userID, note.UserID)
	})

	t.Run("invalid request format", func(t *testing.T) {
		invalidJSON := `{"invalid": "json"`
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes", bytes.NewBufferString(invalidJSON))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("encrypted title too large", func(t *testing.T) {
		req := CreateNoteRequest{
			NoteID:           "new-note-id-2",
			EncryptedTitle:   make([]byte, 65), // Exceeds 64 bytes limit
			EncryptedContent: []byte("encrypted_content"),
		}

		jsonBody, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes", bytes.NewBuffer(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Encrypted title too large (max 64 bytes)", response["error"])
	})

	t.Run("encrypted content too large", func(t *testing.T) {
		req := CreateNoteRequest{
			NoteID:           "new-note-id-3",
			EncryptedTitle:   []byte("encrypted_title"),
			EncryptedContent: make([]byte, 16385), // Exceeds 16KiB limit
		}

		jsonBody, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes", bytes.NewBuffer(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Encrypted content too large (max 16KiB)", response["error"])
	})
}

func TestCreateNoteVersion(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	noteID := "test-note-id"
	createTestNote(t, db, noteID, userID)

	router.POST("/notes/:note_id/versions", func(c *gin.Context) {
		setUserContext(c, userID)
		CreateNoteVersion(c)
	})

	t.Run("successful creation", func(t *testing.T) {
		req := CreateVersionRequest{
			EncryptedTitle:   []byte("new_encrypted_title"),
			EncryptedContent: []byte("new_encrypted_content"),
		}

		jsonBody, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes/"+noteID+"/versions", bytes.NewBuffer(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "New version created successfully", response["message"])
		assert.Equal(t, noteID, response["note_id"])
		assert.Equal(t, float64(2), response["version_no"])

		// Verify version was created in database
		var version model.NoteVersion
		err = db.Where("note_id = ? AND version_no = ?", noteID, 2).First(&version).Error
		require.NoError(t, err)
	})

	t.Run("note not found", func(t *testing.T) {
		req := CreateVersionRequest{
			EncryptedTitle:   []byte("encrypted_title"),
			EncryptedContent: []byte("encrypted_content"),
		}

		jsonBody, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes/nonexistent/versions", bytes.NewBuffer(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("access denied - different user", func(t *testing.T) {
		otherUser := createTestUser(t, db, "")
		otherUserID := otherUser.ID.String()

		router.POST("/notes/:note_id/versions/denied", func(c *gin.Context) {
			setUserContext(c, otherUserID)
			CreateNoteVersion(c)
		})

		req := CreateVersionRequest{
			EncryptedTitle:   []byte("encrypted_title"),
			EncryptedContent: []byte("encrypted_content"),
		}

		jsonBody, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		httpReq, _ := http.NewRequest("POST", "/notes/"+noteID+"/versions/denied", bytes.NewBuffer(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestDeleteNote(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	noteID := "test-note-id"
	createTestNote(t, db, noteID, userID)

	router.DELETE("/notes/:note_id", func(c *gin.Context) {
		setUserContext(c, userID)
		DeleteNote(c)
	})

	t.Run("successful deletion", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/notes/"+noteID, nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Note deleted successfully", response["message"])
		assert.Equal(t, noteID, response["note_id"])

		// Verify note was deleted from database
		var note model.Note
		err = db.Where("note_id = ?", noteID).First(&note).Error
		assert.Error(t, err)
		assert.Equal(t, gorm.ErrRecordNotFound, err)
	})

	t.Run("note not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/notes/nonexistent", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestGetUserStats(t *testing.T) {
	router, db, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	user := createTestUser(t, db, "")
	userID := user.ID.String()
	createTestNote(t, db, "note1", userID)
	createTestNote(t, db, "note2", userID)

	router.GET("/stats", func(c *gin.Context) {
		setUserContext(c, userID)
		GetUserStats(c)
	})

	t.Run("successful retrieval", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/stats", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(2), response["total_notes"])
		assert.Equal(t, userID, response["user_id"])
	})
}

func TestGetUserID(t *testing.T) {
	router, _, cleanup := setupNoteControllerTest(t)
	defer cleanup()

	t.Run("valid user context", func(t *testing.T) {
		router.GET("/test", func(c *gin.Context) {
			setUserContext(c, "test-user-id")
			userID := getUserID(c)
			c.JSON(http.StatusOK, gin.H{"user_id": userID})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "test-user-id", response["user_id"])
	})

	t.Run("no user context", func(t *testing.T) {
		router.GET("/test-no-user", func(c *gin.Context) {
			userID := getUserID(c)
			c.JSON(http.StatusOK, gin.H{"user_id": userID})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-no-user", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "", response["user_id"])
	})

	t.Run("invalid user context type", func(t *testing.T) {
		router.GET("/test-invalid-user", func(c *gin.Context) {
			c.Set("user", "invalid-user-type")
			userID := getUserID(c)
			c.JSON(http.StatusOK, gin.H{"user_id": userID})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-invalid-user", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "", response["user_id"])
	})
}

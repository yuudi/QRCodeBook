package controller

import (
	"net/http"
	"strconv"
	"yuudi/qrcodebook/src/internal/model"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Response structures
type NoteListResponse struct {
	Notes      []model.NoteWithLatestVersion `json:"notes"`
	Total      int64                         `json:"total"`
	Page       int                           `json:"page"`
	PageSize   int                           `json:"page_size"`
	TotalPages int                           `json:"total_pages"`
}

type NoteVersionListResponse struct {
	Versions   []model.NoteVersionInfo `json:"versions"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PageSize   int                     `json:"page_size"`
	TotalPages int                     `json:"total_pages"`
}

type CreateNoteRequest struct {
	NoteID           string `json:"note_id" binding:"required"`
	EncryptedTitle   []byte `json:"encrypted_title" binding:"required"`
	EncryptedContent []byte `json:"encrypted_content" binding:"required"`
}

type CreateVersionRequest struct {
	EncryptedTitle   []byte `json:"encrypted_title" binding:"required"`
	EncryptedContent []byte `json:"encrypted_content" binding:"required"`
}

// getUserID extracts user ID from the authenticated context
func getUserID(c *gin.Context) string {
	user, exists := c.Get("user")
	if !exists {
		return ""
	}
	userJWT, ok := user.(model.UserJWTContent)
	if !ok {
		return ""
	}
	return userJWT.ID
}

// GetUserNotes retrieves all notes for the authenticated user with pagination
func GetUserNotes(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	notes, total, err := model.GetUserLatestNotes(model.DB, userID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve notes"})
		return
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	c.JSON(http.StatusOK, NoteListResponse{
		Notes:      notes,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// GetUserNotesBasic retrieves basic note information without content (lightweight)
func GetUserNotesBasic(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	notes, total, err := model.GetUserNotesBasicInfo(model.DB, userID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve notes"})
		return
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	c.JSON(http.StatusOK, gin.H{
		"notes":       notes,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// GetNoteContent retrieves the latest content of a specific note
func GetNoteContent(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	noteID := c.Param("note_id")
	if noteID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Note ID is required"})
		return
	}

	version, err := model.GetNoteLatestContentByUser(model.DB, noteID, userID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Note not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve note"})
		}
		return
	}

	c.JSON(http.StatusOK, version)
}

// GetNoteVersionContent retrieves a specific version of a note
func GetNoteVersionContent(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	noteID := c.Param("note_id")
	versionNoStr := c.Param("version_no")

	if noteID == "" || versionNoStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Note ID and version number are required"})
		return
	}

	versionNo, err := strconv.Atoi(versionNoStr)
	if err != nil || versionNo < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid version number"})
		return
	}

	// Verify ownership first
	owner, err := model.GetNoteOwner(model.DB, noteID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Note not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify note ownership"})
		}
		return
	}

	if owner != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	version, err := model.GetNoteVersionContent(model.DB, noteID, versionNo)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve version"})
		}
		return
	}

	c.JSON(http.StatusOK, version)
}

// GetNoteVersions retrieves all versions of a note
func GetNoteVersions(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	noteID := c.Param("note_id")
	if noteID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Note ID is required"})
		return
	}

	// Verify ownership
	owner, err := model.GetNoteOwner(model.DB, noteID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Note not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify note ownership"})
		}
		return
	}

	if owner != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	versions, total, err := model.GetNoteVersions(model.DB, noteID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve versions"})
		return
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	c.JSON(http.StatusOK, NoteVersionListResponse{
		Versions:   versions,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// CreateNote creates a new note with its first version
func CreateNote(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	var req CreateNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Validate encrypted content size
	if len(req.EncryptedTitle) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Encrypted title too large (max 64 bytes)"})
		return
	}
	if len(req.EncryptedContent) > 16384 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Encrypted content too large (max 16KiB)"})
		return
	}

	err := model.CreateNoteWithVersion(model.DB, req.NoteID, userID, req.EncryptedTitle, req.EncryptedContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create note"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Note created successfully",
		"note_id": req.NoteID,
	})
}

// CreateNoteVersion creates a new version for an existing note
func CreateNoteVersion(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	noteID := c.Param("note_id")
	if noteID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Note ID is required"})
		return
	}

	// Verify ownership
	owner, err := model.GetNoteOwner(model.DB, noteID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Note not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify note ownership"})
		}
		return
	}

	if owner != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	var req CreateVersionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Validate encrypted content size
	if len(req.EncryptedTitle) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Encrypted title too large (max 64 bytes)"})
		return
	}
	if len(req.EncryptedContent) > 16384 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Encrypted content too large (max 16KiB)"})
		return
	}

	newVersion, err := model.CreateNewVersion(model.DB, noteID, req.EncryptedTitle, req.EncryptedContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create new version"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":    "New version created successfully",
		"note_id":    noteID,
		"version_no": newVersion.VersionNo,
	})
}

// DeleteNote deletes a note and all its versions
func DeleteNote(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	noteID := c.Param("note_id")
	if noteID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Note ID is required"})
		return
	}

	err := model.DeleteNote(model.DB, noteID, userID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Note not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete note"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Note deleted successfully",
		"note_id": noteID,
	})
}

// GetUserStats returns statistics about user's notes
func GetUserStats(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	count, err := model.GetUserNoteCount(model.DB, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get statistics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_notes": count,
		"user_id":     userID,
	})
}

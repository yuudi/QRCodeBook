package model

import (
	"time"

	"gorm.io/gorm"
)

type Note struct {
	NoteID          string    `gorm:"primaryKey;type:varchar(255);not null" json:"id"`
	UserID          string    `gorm:"index;type:varchar(255);not null" json:"user_id"`
	LatestVersionNo int       `gorm:"default:1;not null;check:latest_version_no >= 1" json:"latest_version_no"`
	CreatedAt       time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime;not null" json:"updated_at"`
}

type NoteVersion struct {
	NoteID           string    `gorm:"primaryKey;type:varchar(255);not null" json:"note_id"`
	VersionNo        int       `gorm:"primaryKey;not null;check:version_no >= 1" json:"version_no"`
	EncryptedTitle   []byte    `gorm:"size:64;not null" json:"encrypted_title"`
	EncryptedContent []byte    `gorm:"size:16384;not null" json:"encrypted_content"`
	CreatedAt        time.Time `gorm:"autoCreateTime;not null" json:"created_at"`

	// Foreign key relationship
	Note Note `gorm:"foreignKey:NoteID;references:NoteID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
}

// NoteWithLatestVersion represents a note with its latest version content
type NoteWithLatestVersion struct {
	Note
	LatestVersion NoteVersion `json:"latest_version"`
}

// NoteVersionInfo represents note version information without content
type NoteVersionInfo struct {
	NoteID    string    `json:"note_id"`
	VersionNo int       `json:"version_no"`
	CreatedAt time.Time `json:"created_at"`
}

// GetUserLatestNotes retrieves all latest notes for a user with pagination
func GetUserLatestNotes(db *gorm.DB, userID string, page, pageSize int) ([]NoteWithLatestVersion, int64, error) {
	var notes []Note
	var total int64

	// Count total notes for the user
	if err := db.Model(&Note{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Get notes with pagination
	if err := db.Where("user_id = ?", userID).
		Order("updated_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&notes).Error; err != nil {
		return nil, 0, err
	}

	var result []NoteWithLatestVersion
	for _, note := range notes {
		var latestVersion NoteVersion
		if err := db.Where("note_id = ? AND version_no = ?", note.NoteID, note.LatestVersionNo).
			First(&latestVersion).Error; err != nil {
			return nil, 0, err
		}

		result = append(result, NoteWithLatestVersion{
			Note:          note,
			LatestVersion: latestVersion,
		})
	}

	return result, total, nil
}

// GetNoteVersions retrieves all versions of a specific note with ID and timestamp (with pagination)
func GetNoteVersions(db *gorm.DB, noteID string, page, pageSize int) ([]NoteVersionInfo, int64, error) {
	var versions []NoteVersionInfo
	var total int64

	// Count total versions for the note
	if err := db.Model(&NoteVersion{}).Where("note_id = ?", noteID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Get versions with pagination
	if err := db.Model(&NoteVersion{}).
		Select("note_id, version_no, created_at").
		Where("note_id = ?", noteID).
		Order("version_no DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&versions).Error; err != nil {
		return nil, 0, err
	}

	return versions, total, nil
}

// GetNoteLatestContent retrieves the latest version content of a specific note
func GetNoteLatestContent(db *gorm.DB, noteID string) (*NoteVersion, error) {
	var note Note
	if err := db.Where("note_id = ?", noteID).First(&note).Error; err != nil {
		return nil, err
	}

	var version NoteVersion
	if err := db.Where("note_id = ? AND version_no = ?", noteID, note.LatestVersionNo).
		First(&version).Error; err != nil {
		return nil, err
	}

	return &version, nil
}

// GetNoteVersionContent retrieves a specific version content of a note
func GetNoteVersionContent(db *gorm.DB, noteID string, versionNo int) (*NoteVersion, error) {
	var version NoteVersion
	if err := db.Where("note_id = ? AND version_no = ?", noteID, versionNo).
		First(&version).Error; err != nil {
		return nil, err
	}

	return &version, nil
}

// GetNoteLatestContentByUser retrieves the latest version content of a note with user verification
func GetNoteLatestContentByUser(db *gorm.DB, noteID, userID string) (*NoteVersion, error) {
	var note Note
	if err := db.Where("note_id = ? AND user_id = ?", noteID, userID).First(&note).Error; err != nil {
		return nil, err
	}

	var version NoteVersion
	if err := db.Where("note_id = ? AND version_no = ?", noteID, note.LatestVersionNo).
		First(&version).Error; err != nil {
		return nil, err
	}

	return &version, nil
}

// CreateNoteWithVersion creates a new note and its first version
func CreateNoteWithVersion(db *gorm.DB, noteID, userID string, encryptedTitle, encryptedContent []byte) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Create note
		note := Note{
			NoteID:          noteID,
			UserID:          userID,
			LatestVersionNo: 1,
		}
		if err := tx.Create(&note).Error; err != nil {
			return err
		}

		// Create first version
		version := NoteVersion{
			NoteID:           noteID,
			VersionNo:        1,
			EncryptedTitle:   encryptedTitle,
			EncryptedContent: encryptedContent,
		}
		if err := tx.Create(&version).Error; err != nil {
			return err
		}

		return nil
	})
}

// CreateNewVersion creates a new version for an existing note
func CreateNewVersion(db *gorm.DB, noteID string, encryptedTitle, encryptedContent []byte) (*NoteVersion, error) {
	var newVersion *NoteVersion

	err := db.Transaction(func(tx *gorm.DB) error {
		// Get current note
		var note Note
		if err := tx.Where("note_id = ?", noteID).First(&note).Error; err != nil {
			return err
		}

		// Calculate new version number
		newVersionNo := note.LatestVersionNo + 1

		// Create new version
		newVersion = &NoteVersion{
			NoteID:           noteID,
			VersionNo:        newVersionNo,
			EncryptedTitle:   encryptedTitle,
			EncryptedContent: encryptedContent,
		}
		if err := tx.Create(newVersion).Error; err != nil {
			return err
		}

		// Update note's latest version number
		if err := tx.Model(&note).Update("latest_version_no", newVersionNo).Error; err != nil {
			return err
		}

		return nil
	})

	return newVersion, err
}

// DeleteNote deletes a note and all its versions
func DeleteNote(db *gorm.DB, noteID, userID string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Verify ownership
		var note Note
		if err := tx.Where("note_id = ? AND user_id = ?", noteID, userID).First(&note).Error; err != nil {
			return err
		}

		// Delete all versions (will cascade due to foreign key constraints)
		if err := tx.Where("note_id = ?", noteID).Delete(&NoteVersion{}).Error; err != nil {
			return err
		}

		// Delete note
		if err := tx.Delete(&note).Error; err != nil {
			return err
		}

		return nil
	})
}

// GetUserNoteCount returns the total number of notes for a user
func GetUserNoteCount(db *gorm.DB, userID string) (int64, error) {
	var count int64
	err := db.Model(&Note{}).Where("user_id = ?", userID).Count(&count).Error
	return count, err
}

// GetNoteOwner returns the owner user ID of a note
func GetNoteOwner(db *gorm.DB, noteID string) (string, error) {
	var note Note
	if err := db.Select("user_id").Where("note_id = ?", noteID).First(&note).Error; err != nil {
		return "", err
	}
	return note.UserID, nil
}

// GetUserNotesBasicInfo retrieves basic info of user's notes without content (lightweight)
func GetUserNotesBasicInfo(db *gorm.DB, userID string, page, pageSize int) ([]Note, int64, error) {
	var notes []Note
	var total int64

	// Count total notes for the user
	if err := db.Model(&Note{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Get notes with pagination (without version content)
	if err := db.Where("user_id = ?", userID).
		Order("updated_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&notes).Error; err != nil {
		return nil, 0, err
	}

	return notes, total, nil
}

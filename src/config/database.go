package config

import (
	"fmt"
	"yuudi/qrcodebook/src/internal/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	host := MustGetEnv("DB_HOST")
	user := MustGetEnv("DB_USER")
	password := MustGetEnv("DB_PASSWORD")
	dbname := MustGetEnv("DB_NAME")
	port := MustGetEnv("DB_PORT")
	sslmode := MustGetEnv("DB_SSLMODE")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s", host, user, password, dbname, port, sslmode)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	db.AutoMigrate(&model.User{}, &model.Credential{})
	DB = db
}

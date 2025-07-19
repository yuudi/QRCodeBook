package model

import (
	"fmt"
	"yuudi/qrcodebook/src/utils"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	host := utils.MustGetEnv("DB_HOST")
	user := utils.MustGetEnv("DB_USER")
	password := utils.MustGetEnv("DB_PASSWORD")
	dbname := utils.MustGetEnv("DB_NAME")
	port := utils.MustGetEnv("DB_PORT")
	sslmode := utils.MustGetEnv("DB_SSLMODE")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s", host, user, password, dbname, port, sslmode)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	db.AutoMigrate(&User{}, &Credential{})
	DB = db
}

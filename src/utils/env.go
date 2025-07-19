package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvFromFile(path string) error {
	return godotenv.Load(path)
}

func GetEnv(key string) string {
	value := os.Getenv(key)
	return value
}

func MustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Required environment variable %s not set", key)
	}
	return value
}

package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// config holds all configuration for the application
type config struct {
	Mode             string
	Port             int
	ClusterSecretKey string
	Database         databaseConfig
	WebAuthn         webAuthnConfig
}

// databaseConfig holds database configuration
type databaseConfig struct {
	Host     string
	User     string
	Password string
	Name     string
	Port     int
	SSLMode  string
}

// webAuthnConfig holds WebAuthn configuration
type webAuthnConfig struct {
	RPID    string
	RPName  string
	Origins []string
}

var AppConfig *config

func Init() {
	// Try to load environment variables from .env file
	_ = godotenv.Load()
	AppConfig = loadConfig()
}

// LoadEnvFromFile loads environment variables from a specific file
func LoadEnvFromFile(path string) error {
	err := godotenv.Load(path)
	if err != nil {
		return err
	}
	AppConfig = loadConfig()
	return nil
}

// loadConfig loads configuration from environment variables
func loadConfig() *config {
	config := &config{
		Mode:             getEnv("MODE", "debug"),
		Port:             getEnvAsInt("PORT", 8080),
		ClusterSecretKey: mustGetEnv("CLUSTER_SECRET_KEY"),
		Database: databaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			User:     getEnv("DB_USER", "qrcodebook"),
			Password: mustGetEnv("DB_PASSWORD"),
			Name:     getEnv("DB_NAME", "qrcodebook"),
			Port:     getEnvAsInt("DB_PORT", 5432),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		WebAuthn: webAuthnConfig{
			RPID:    mustGetEnv("WEBAUTHN_RPID"),
			RPName:  getEnv("WEBAUTHN_RP_NAME", "qrcodebook"),
			Origins: getEnvAsSlice("WEBAUTHN_ORIGINS", []string{}),
		},
	}

	return config
}

// getEnv gets an environment variable with a fallback value
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// getEnvAsInt gets an environment variable as integer with a fallback value
func getEnvAsInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

// getEnvAsSlice gets an environment variable as slice with a fallback value
func getEnvAsSlice(key string, fallback []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return fallback
}

// mustGetEnv gets an environment variable and panics if it's not set
func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("Environment variable " + key + " is required but not set")
	}
	return value
}

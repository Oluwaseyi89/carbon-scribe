package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	AWS      AWSConfig
	Database DatabaseConfig
	Server   ServerConfig
}

// AWSConfig holds AWS-specific configuration
type AWSConfig struct {
	Region                  string
	AccessKeyID             string
	SecretAccessKey         string
	SESFromEmail            string
	SNSSMSSenderID          string
	DynamoDBEndpoint        string
	APIGatewayWebSocketURL  string
	APIGatewayManagementURL string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	PostgresURL string
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port            string
	WebSocketPort   string
	ShutdownTimeout time.Duration
}

// NotificationConfig holds notification-specific configuration
type NotificationConfig struct {
	MaxRetries          int
	RetryBaseDelay      time.Duration
	MaxQueuedMessages   int
	DeadLetterQueueURL  string
	DefaultQuietStart   string // HH:MM format
	DefaultQuietEnd     string // HH:MM format
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		AWS: AWSConfig{
			Region:                  getEnv("AWS_REGION", "us-east-1"),
			AccessKeyID:             getEnv("AWS_ACCESS_KEY_ID", ""),
			SecretAccessKey:         getEnv("AWS_SECRET_ACCESS_KEY", ""),
			SESFromEmail:            getEnv("AWS_SES_FROM_EMAIL", "noreply@carbonscribe.com"),
			SNSSMSSenderID:          getEnv("AWS_SNS_SMS_SENDER_ID", "CarbonScribe"),
			DynamoDBEndpoint:        getEnv("AWS_DYNAMODB_ENDPOINT", ""),
			APIGatewayWebSocketURL:  getEnv("AWS_APIGW_WEBSOCKET_URL", ""),
			APIGatewayManagementURL: getEnv("AWS_APIGW_MANAGEMENT_URL", ""),
		},
		Database: DatabaseConfig{
			PostgresURL: getEnv("DATABASE_URL", ""),
		},
		Server: ServerConfig{
			Port:            getEnv("PORT", "8080"),
			WebSocketPort:   getEnv("WEBSOCKET_PORT", "8081"),
			ShutdownTimeout: getDurationEnv("SHUTDOWN_TIMEOUT", 30*time.Second),
		},
	}
}

// LoadNotificationConfig loads notification-specific configuration
func LoadNotificationConfig() *NotificationConfig {
	return &NotificationConfig{
		MaxRetries:         getIntEnv("NOTIFICATION_MAX_RETRIES", 3),
		RetryBaseDelay:     getDurationEnv("NOTIFICATION_RETRY_BASE_DELAY", 1*time.Second),
		MaxQueuedMessages:  getIntEnv("NOTIFICATION_MAX_QUEUED_MESSAGES", 100),
		DeadLetterQueueURL: getEnv("NOTIFICATION_DLQ_URL", ""),
		DefaultQuietStart:  getEnv("NOTIFICATION_DEFAULT_QUIET_START", "22:00"),
		DefaultQuietEnd:    getEnv("NOTIFICATION_DEFAULT_QUIET_END", "08:00"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

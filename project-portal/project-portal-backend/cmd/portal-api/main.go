package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"carbon-scribe/project-portal/project-portal-backend/internal/config"
	"carbon-scribe/project-portal/project-portal-backend/internal/notifications"
	"carbon-scribe/project-portal/project-portal-backend/internal/notifications/channels"
	"carbon-scribe/project-portal/project-portal-backend/internal/notifications/rules"
	"carbon-scribe/project-portal/project-portal-backend/internal/notifications/templates"
	awspkg "carbon-scribe/project-portal/project-portal-backend/pkg/aws"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()
	notifCfg := config.LoadNotificationConfig()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize AWS clients
	dynamoDBClient, err := awspkg.NewDynamoDBClient(ctx, awspkg.DynamoDBConfig{
		Region:          cfg.AWS.Region,
		Endpoint:        cfg.AWS.DynamoDBEndpoint,
		AccessKeyID:     cfg.AWS.AccessKeyID,
		SecretAccessKey: cfg.AWS.SecretAccessKey,
	})
	if err != nil {
		log.Fatalf("Failed to create DynamoDB client: %v", err)
	}

	sesClient, err := awspkg.NewSESClient(ctx, awspkg.SESConfig{
		Region:          cfg.AWS.Region,
		AccessKeyID:     cfg.AWS.AccessKeyID,
		SecretAccessKey: cfg.AWS.SecretAccessKey,
		FromEmail:       cfg.AWS.SESFromEmail,
	})
	if err != nil {
		log.Fatalf("Failed to create SES client: %v", err)
	}

	snsClient, err := awspkg.NewSNSClient(ctx, awspkg.SNSConfig{
		Region:          cfg.AWS.Region,
		AccessKeyID:     cfg.AWS.AccessKeyID,
		SecretAccessKey: cfg.AWS.SecretAccessKey,
		SMSSenderID:     cfg.AWS.SNSSMSSenderID,
	})
	if err != nil {
		log.Fatalf("Failed to create SNS client: %v", err)
	}

	apiGatewayClient, err := awspkg.NewAPIGatewayClient(ctx, awspkg.APIGatewayConfig{
		Region:          cfg.AWS.Region,
		Endpoint:        cfg.AWS.APIGatewayManagementURL,
		AccessKeyID:     cfg.AWS.AccessKeyID,
		SecretAccessKey: cfg.AWS.SecretAccessKey,
	})
	if err != nil {
		log.Fatalf("Failed to create API Gateway client: %v", err)
	}

	// Initialize notification repository
	tableNames := notifications.DefaultTableNames()
	repo := notifications.NewRepository(dynamoDBClient, tableNames)

	// Initialize template manager
	templateStore := templates.NewStore(dynamoDBClient, tableNames.Templates)
	templateManager := templates.NewManager(templateStore)

	// Initialize rule engine
	ruleEngine := rules.NewEngine(repo)

	// Initialize notification channels
	emailChannel := channels.NewEmailChannel(sesClient)
	smsChannel := channels.NewSMSChannel(snsClient)
	wsChannel := channels.NewWebSocketChannel(apiGatewayClient, repo)

	// Initialize notification service
	notificationService := notifications.NewService(notifications.ServiceConfig{
		Repository:      repo,
		TemplateManager: templateManager,
		RuleEngine:      ruleEngine,
		EmailChannel:    emailChannel,
		SMSChannel:      smsChannel,
		WSChannel:       wsChannel,
		Config:          notifCfg,
	})

	// Initialize notification handler
	notificationHandler := notifications.NewHandler(notificationService)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "carbonscribe-portal-api",
		})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Register notification routes
		notificationHandler.RegisterRoutes(v1)

		// TODO: Add other module routes here
		// projectHandler.RegisterRoutes(v1)
		// documentHandler.RegisterRoutes(v1)
		// financingHandler.RegisterRoutes(v1)
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on port %s", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	// Gracefully shutdown the server
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited properly")
}

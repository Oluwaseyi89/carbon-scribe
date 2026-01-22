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
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"carbon-scribe/project-portal/project-portal-backend/internal/config"
	"carbon-scribe/project-portal/project-portal-backend/internal/financing"
	"carbon-scribe/project-portal/project-portal-backend/internal/financing/calculation"
	"carbon-scribe/project-portal/project-portal/backend/internal/financing/tokenization"
	"carbon-scribe/project-portal/project-portal-backend/internal/financing/sales"
	"carbon-scribe/project-portal/project-portal/backend/internal/financing/payments"
)

func main() {
	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.json"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	db, err := sqlx.Connect("postgres", cfg.Database.GetDatabaseURL())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run database migrations
	if err := runMigrations(db, cfg.Database.MigrationsPath); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize repositories
	repository := financing.NewSQLRepository(db)

	// Initialize services
	calculationEngine := calculation.NewEngine()
	
	// Initialize Stellar client
	issuerAccount := &tokenization.StellarAccount{
		PublicKey: getStellarPublicKey(cfg.Stellar.IssuerAccount.SecretKey),
		SecretKey: cfg.Stellar.IssuerAccount.SecretKey,
	}

	stellarClient := tokenization.NewStellarClient(
		cfg.Stellar.HorizonURL,
		cfg.Stellar.SorobanURL,
		cfg.Stellar.NetworkPassphrase,
		issuerAccount,
	)

	// Initialize workflow
	workflowConfig := &tokenization.WorkflowConfig{
		MaxRetries:          cfg.Financing.TokenMinting.MaxRetries,
		RetryDelay:          cfg.Financing.TokenMinting.RetryDelay,
		ConfirmationTimeout:   cfg.Financing.TokenMinting.ConfirmationTimeout,
		BatchSize:           cfg.Financing.TokenMinting.MaxBatchSize,
		GasOptimization:     cfg.Financing.TokenMinting.GasOptimization,
	}

	tokenizationWorkflow := tokenization.NewWorkflow(stellarClient, repository, nil, workflowConfig)

	// Initialize managers
	pricingEngine := sales.NewPricingEngine(repository, &sales.PricingConfig{
		DefaultBasePrice:     cfg.Financing.Pricing.DefaultBasePrice,
		PriceVarianceLimit:   cfg.Financing.Pricing.PriceVarianceLimit,
		MinPrice:            cfg.Financing.Pricing.MinPrice,
		MaxPrice:            cfg.Financing.Pricing.MaxPrice,
		QualityWeight:        cfg.Financing.Pricing.QualityWeight,
		VintageWeight:        cfg.Financing.Pricing.VintageWeight,
		RegionWeight:         cfg.Financing.Pricing.RegionWeight,
		MarketWeight:         cfg.Financing.Pricing.MarketWeight,
		OracleWeight:         cfg.Financing.Pricing.OracleWeight,
		PriceUpdateInterval:  cfg.Financing.Pricing.PriceUpdateInterval,
	})

	forwardSaleManager := sales.NewForwardSaleManager(repository, pricingEngine, &sales.ForwardSaleConfig{
		MinDepositPercent:     cfg.Financing.ForwardSales.MinDepositPercent,
		MaxDepositPercent:     cfg.Financing.ForwardSales.MaxDepositPercent,
		DefaultDepositPercent: cfg.Financing.ForwardSales.DefaultDepositPercent,
		MinDeliveryDays:       cfg.Financing.ForwardSales.MinDeliveryDays,
		MaxDeliveryDays:       cfg.Financing.ForwardSales.MaxDeliveryDays,
		ContractValidityDays:  cfg.Financing.ForwardSales.ContractValidityDays,
		AutoCancelDays:        cfg.Financing.ForwardSales.AutoCancelDays,
		PriceAdjustmentRate:   cfg.Financing.ForwardSales.PriceAdjustmentRate,
	})

	auctionManager := sales.NewAuctionManager(repository, pricingEngine, &sales.AuctionConfig{
		MinBidIncrement:      cfg.Financing.Auctions.MinBidIncrement,
		MaxBidIncrement:      cfg.Financing.Auctions.MaxBidIncrement,
		DefaultBidIncrement:  cfg.Financing.Auctions.DefaultBidIncrement,
		MinReservePrice:      cfg.Financing.Auctions.MinReservePrice,
		MaxReservePrice:      cfg.Financing.Auctions.MaxReservePrice,
		DefaultReservePrice:  cfg.Financing.Auctions.DefaultReservePrice,
		AutoExtendMinutes:     cfg.Financing.Auctions.AutoExtendMinutes,
		BidDepositPercent:    cfg.Financing.Auctions.BidDepositPercent,
		MaxActiveAuctions:    cfg.Financing.Auctions.MaxActiveAuctions,
		AuctionDurationHours:  cfg.Financing.Auctions.AuctionDurationHours,
	})

	paymentRegistry := payments.NewPaymentProcessorRegistry(&payments.ProcessorConfig{
		Stripe:      cfg.Payments.Stripe,
		PayPal:      cfg.Payments.PayPal,
		M_Pesa:      cfg.Payments.M_Pesa,
		BankTransfer: cfg.Payments.BankTransfer,
	})

	distributionManager := payments.NewRevenueDistributionManager(repository, &payments.DistributionConfig{
		DefaultPlatformFee:    cfg.Financing.RevenueDistribution.DefaultPlatformFee,
		MinPlatformFee:        cfg.Financing.RevenueDistribution.MinPlatformFee,
		MaxPlatformFee:        cfg.Financing.RevenueDistribution.MaxPlatformFee,
		MinDistributionAmount:  cfg.Financing.RevenueDistribution.MinDistributionAmount,
		MaxBatchSize:          cfg.Financing.RevenueDistribution.MaxBatchSize,
		PaymentTimeoutMinutes:  cfg.Financing.RevenueDistribution.PaymentTimeoutMinutes,
		RetryAttempts:         cfg.Financing.RevenueDistribution.RetryAttempts,
		RetryDelayMinutes:     cfg.Financing.RevenueDistribution.RetryDelayMinutes,
		AutoApproveThreshold:   cfg.Financing.RevenueDistribution.AutoApproveThreshold,
	})

	// Initialize service layer
	financingService := financing.NewService(
		repository,
		calculationEngine,
		tokenizationWorkflow,
		forwardSaleManager,
		pricingEngine,
		auctionManager,
		distributionManager,
		paymentRegistry,
	)

	// Initialize HTTP handlers
	financingHandler := financing.NewHandler(
		calculationEngine,
		tokenizationWorkflow,
		forwardSaleManager,
		pricingEngine,
		auctionManager,
		distributionManager,
		paymentRegistry,
	)

	// Setup Gin router
	router := setupRouter(cfg, financingHandler)

	// Start HTTP server
	server := &http.Server{
		Addr:         cfg.Server.GetServerAddr(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		<-sigChan
		log.Println("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("Starting server on %s", cfg.Server.GetServerAddr())
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("Server stopped")
}

// setupRouter sets up the Gin router with middleware and routes
func setupRouter(cfg *config.Config, financingHandler *financing.Handler) *gin.Engine {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	router := gin.New()

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(corsMiddleware(cfg.Security.CORS))
	router.Use(rateLimitMiddleware(cfg.Security.RateLimiting))
	router.Use(requestIDMiddleware())

	// Health check endpoint
	router.GET("/health", healthCheck)

	// API version 1 routes
	v1 := router.Group("/api/v1")
	{
		// Register financing routes
		financingHandler.RegisterRoutes(v1)

		// TODO: Add other module routes (projects, users, etc.)
	}

	return router
}

// corsMiddleware adds CORS headers
func corsMiddleware(corsConfig config.CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range corsConfig.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// rateLimitMiddleware adds rate limiting
func rateLimitMiddleware(rateLimitConfig config.RateLimitConfig) gin.HandlerFunc {
	if !rateLimitConfig.Enabled {
		return gin.HandlerFunc(func(c *gin.Context) {
			c.Next()
		})
	}

	// TODO: Implement actual rate limiting
	// For now, just pass through
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Next()
	})
}

// requestIDMiddleware adds a unique request ID
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// healthCheck returns the health status of the service
func healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"service":   "carbon-scribe-financing",
	})
}

// runMigrations runs database migrations
func runMigrations(db *sqlx.DB, migrationsPath string) error {
	// TODO: Implement proper migration runner
	// For now, just log that migrations would run
	log.Printf("Would run migrations from: %s", migrationsPath)
	return nil
}

// getStellarPublicKey extracts public key from secret seed
func getStellarPublicKey(secretSeed string) string {
	// In a real implementation, this would properly decode the Stellar secret seed
	// For now, return a mock public key
	return "GABCDEF1234567890ABCDEF1234567890ABCDEF12"
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	// Simple request ID generation
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
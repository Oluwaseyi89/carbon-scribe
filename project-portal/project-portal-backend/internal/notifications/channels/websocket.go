package channels

import (
	"context"
	"errors"
	"fmt"
	"time"

	"carbon-scribe/project-portal/project-portal-backend/internal/notifications"
	"carbon-scribe/project-portal/project-portal-backend/pkg/aws"
)

// WebSocketSender defines the interface for sending WebSocket notifications.
type WebSocketSender interface {
	Send(ctx context.Context, userID string, notification *notifications.Notification) error
	Broadcast(ctx context.Context, projectID string, notification *notifications.Notification) (int, error)
}

// WebSocketChannel implements WebSocket notification delivery.
type WebSocketChannel struct {
	repo        notifications.Repository
	apiClient   *aws.APIGatewayClient
	retryLimit  int
}

// NewWebSocketChannel creates a new WebSocket notification channel.
func NewWebSocketChannel(repo notifications.Repository, apiClient *aws.APIGatewayClient) *WebSocketChannel {
	return &WebSocketChannel{
		repo:       repo,
		apiClient:  apiClient,
		retryLimit: 3,
	}
}

// Send sends a notification to all active WebSocket connections for a user.
func (w *WebSocketChannel) Send(ctx context.Context, userID string, notification *notifications.Notification) error {
	if userID == "" {
		return errors.New("user ID is required")
	}
	if notification == nil {
		return errors.New("notification is required")
	}

	conns, err := w.repo.ListConnections(ctx, "", userID)
	if err != nil {
		return fmt.Errorf("failed to list connections: %w", err)
	}

	if len(conns) == 0 {
		return fmt.Errorf("no active connections for user %s", userID)
	}

	var lastErr error
	sentCount := 0

	for _, conn := range conns {
		for attempt := 0; attempt <= w.retryLimit; attempt++ {
			err := w.sendToConnection(ctx, conn.ConnectionID, notification)
			if err == nil {
				sentCount++
				break
			}
			lastErr = err
			if attempt < w.retryLimit {
				time.Sleep(time.Duration((attempt + 1) * 100) * time.Millisecond)
			}
		}
	}

	if sentCount == 0 && lastErr != nil {
		return lastErr
	}

	return nil
}

// Broadcast sends a notification to all connections in a project.
func (w *WebSocketChannel) Broadcast(ctx context.Context, projectID string, notification *notifications.Notification) (int, error) {
	if projectID == "" {
		return 0, errors.New("project ID is required")
	}
	if notification == nil {
		return 0, errors.New("notification is required")
	}

	conns, err := w.repo.ListConnections(ctx, projectID, "")
	if err != nil {
		return 0, fmt.Errorf("failed to list connections: %w", err)
	}

	sentCount := 0
	for _, conn := range conns {
		for attempt := 0; attempt <= w.retryLimit; attempt++ {
			err := w.sendToConnection(ctx, conn.ConnectionID, notification)
			if err == nil {
				sentCount++
				break
			}
			if attempt < w.retryLimit {
				time.Sleep(time.Duration((attempt + 1) * 100) * time.Millisecond)
			}
		}
	}

	return sentCount, nil
}

// sendToConnection sends a notification to a single WebSocket connection.
func (w *WebSocketChannel) sendToConnection(ctx context.Context, connectionID string, notification *notifications.Notification) error {
	if w.apiClient != nil {
		return w.apiClient.PostToConnection(ctx, connectionID, notification)
	}
	// If no API client (local dev), just return success (mock delivery)
	return nil
}

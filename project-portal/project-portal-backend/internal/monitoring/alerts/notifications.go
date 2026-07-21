package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"carbon-scribe/project-portal/project-portal-backend/internal/monitoring"
)

// NotificationService handles alert notifications.
type NotificationService struct {
	httpClient *http.Client
}

// NewNotificationService creates a new NotificationService.
func NewNotificationService() *NotificationService {
	return &NotificationService{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendAlert sends a notification for a triggered alert.
func (n *NotificationService) SendAlert(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	if rule.Notification == nil {
		return
	}

	for _, channel := range rule.Notification.Channels {
		switch channel {
		case "email":
			n.sendEmail(ctx, alert, rule)
		case "webhook":
			n.sendWebhook(ctx, alert, rule)
		case "websocket":
			n.sendWebsocket(ctx, alert, rule)
		case "sms":
			n.sendSMS(ctx, alert, rule)
		}
	}
}

// SendAlertResolution sends a notification for a resolved alert.
func (n *NotificationService) SendAlertResolution(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	if rule.Notification == nil {
		return
	}

	for _, channel := range rule.Notification.Channels {
		switch channel {
		case "email":
			n.sendResolutionEmail(ctx, alert, rule)
		case "webhook":
			n.sendResolutionWebhook(ctx, alert, rule)
		case "websocket":
			n.sendResolutionWebsocket(ctx, alert, rule)
		}
	}
}

// sendEmail sends an email notification.
func (n *NotificationService) sendEmail(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	// Placeholder for email integration
	fmt.Printf("[EMAIL] Alert: %s - %s\n", alert.Title, alert.Message)
}

// sendResolutionEmail sends a resolution email notification.
func (n *NotificationService) sendResolutionEmail(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	fmt.Printf("[EMAIL] Resolved: %s - %s\n", alert.Title, alert.Message)
}

// sendWebhook sends a webhook notification.
func (n *NotificationService) sendWebhook(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	if rule.Notification.Webhook == nil {
		return
	}

	payload := map[string]interface{}{
		"id":         alert.ID,
		"title":      alert.Title,
		"message":    alert.Message,
		"severity":   alert.Severity,
		"service":    alert.ServiceName,
		"status":     alert.Status,
		"timestamp":  alert.CreatedAt.Format(time.RFC3339),
		"details":    alert.Details,
		"event_type": "alert_triggered",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rule.Notification.Webhook.URL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range rule.Notification.Webhook.Headers {
		req.Header.Set(key, value)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// sendResolutionWebhook sends a resolution webhook notification.
func (n *NotificationService) sendResolutionWebhook(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	if rule.Notification.Webhook == nil {
		return
	}

	payload := map[string]interface{}{
		"id":         alert.ID,
		"title":      alert.Title,
		"message":    alert.Message,
		"severity":   alert.Severity,
		"service":    alert.ServiceName,
		"status":     "resolved",
		"timestamp":  alert.ResolvedAt.Format(time.RFC3339),
		"details":    alert.Details,
		"event_type": "alert_resolved",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rule.Notification.Webhook.URL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range rule.Notification.Webhook.Headers {
		req.Header.Set(key, value)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// sendWebsocket sends a websocket notification.
func (n *NotificationService) sendWebsocket(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	// Placeholder for websocket integration
	fmt.Printf("[WEBSOCKET] Alert: %s - %s\n", alert.Title, alert.Message)
}

// sendResolutionWebsocket sends a resolution websocket notification.
func (n *NotificationService) sendResolutionWebsocket(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	fmt.Printf("[WEBSOCKET] Resolved: %s - %s\n", alert.Title, alert.Message)
}

// sendSMS sends an SMS notification.
func (n *NotificationService) sendSMS(ctx context.Context, alert *monitoring.SystemAlert, rule *AlertRule) {
	// Placeholder for SMS integration
	fmt.Printf("[SMS] Alert: %s - %s\n", alert.Title, alert.Message)
}

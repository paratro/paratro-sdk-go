package paratro

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// tokenResponse represents the JWT token response (direct, no envelope)
type tokenResponse struct {
	Token     string     `json:"token"`
	ExpiresIn int        `json:"expires_in"`
	TokenType string     `json:"token_type"`
	Client    clientInfo `json:"client"`
}

// clientInfo represents basic client information
type clientInfo struct {
	ClientID         string `json:"client_id"`
	ClientName       string `json:"client_name"`
	Status           string `json:"status"`
	SubscriptionTier string `json:"subscription_tier"`
	MaxWallets       int    `json:"max_wallets"`
}

// tokenManager manages JWT authentication tokens
type tokenManager struct {
	apiKey    string
	apiSecret string
	baseURL   string
	token     string
	expiresAt time.Time
	mu        sync.RWMutex
}

// newTokenManager creates a new tokenManager
func newTokenManager(apiKey, apiSecret, baseURL string) *tokenManager {
	return &tokenManager{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		baseURL:   baseURL,
	}
}

// getToken returns a valid JWT token, refreshing if necessary
func (tm *tokenManager) getToken() (string, error) {
	tm.mu.RLock()
	if tm.token != "" && time.Now().Before(tm.expiresAt) {
		token := tm.token
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	return tm.refreshToken()
}

// refreshToken fetches a new JWT token
func (tm *tokenManager) refreshToken() (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock
	if tm.token != "" && time.Now().Before(tm.expiresAt) {
		return tm.token, nil
	}

	url := fmt.Sprintf("%s/api/v1/auth/token", tm.baseURL)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("X-API-Key", tm.apiKey)
	req.Header.Set("X-API-Secret", tm.apiSecret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute auth request: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status for errors
	if resp.StatusCode >= 400 {
		var errResp struct {
			Code    string `json:"code"`
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return "", fmt.Errorf("auth request failed with status %d", resp.StatusCode)
		}
		return "", fmt.Errorf("auth request failed: %s - %s (type: %s)",
			errResp.Code, errResp.Message, errResp.Type)
	}

	var tokResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	tm.token = tokResp.Token
	// Set expiration to 5 minutes before actual expiration for safety
	tm.expiresAt = time.Now().Add(time.Duration(tokResp.ExpiresIn-300) * time.Second)

	return tm.token, nil
}


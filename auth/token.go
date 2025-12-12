package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TokenResponse represents the JWT token response
type TokenResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
		TokenType string `json:"token_type"`
		Client    struct {
			ClientID         string `json:"client_id"`
			ClientName       string `json:"client_name"`
			Status           string `json:"status"`
			SubscriptionTier string `json:"subscription_tier"`
			MaxWallets       int    `json:"max_wallets"`
		} `json:"client"`
	} `json:"data"`
	TraceID   string `json:"trace_id"`
	Timestamp int64  `json:"timestamp"`
}

// TokenManager manages JWT authentication tokens
type TokenManager struct {
	apiKey    string
	apiSecret string
	baseURL   string
	token     string
	expiresAt time.Time
	mu        sync.RWMutex
}

// NewTokenManager creates a new TokenManager
func NewTokenManager(apiKey, apiSecret, baseURL string) *TokenManager {
	return &TokenManager{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		baseURL:   baseURL,
	}
}

// GetToken returns a valid JWT token, refreshing if necessary
func (tm *TokenManager) GetToken() (string, error) {
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
func (tm *TokenManager) refreshToken() (string, error) {
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

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	if tokenResp.Code != 200000 {
		return "", fmt.Errorf("auth request failed: %s (code: %d)", tokenResp.Message, tokenResp.Code)
	}

	tm.token = tokenResp.Data.Token
	// Set expiration to 5 minutes before actual expiration for safety
	tm.expiresAt = time.Now().Add(time.Duration(tokenResp.Data.ExpiresIn-300) * time.Second)

	return tm.token, nil
}

// Logout invalidates the current token
func (tm *TokenManager) Logout() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.token == "" {
		return nil
	}

	url := fmt.Sprintf("%s/api/v1/auth/logout", tm.baseURL)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tm.token))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute logout request: %w", err)
	}
	defer resp.Body.Close()

	tm.token = ""
	tm.expiresAt = time.Time{}

	return nil
}

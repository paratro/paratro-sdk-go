package paratro

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// tokenRefreshBuffer is how long before the gateway's expiry we stop using a
// token; it absorbs clock skew and in-flight latency.
const tokenRefreshBuffer = 120 * time.Second

// defaultTokenLifetime is used only when the gateway omits expires_in.
const defaultTokenLifetime = 900 * time.Second

// tokenManager manages JWT authentication tokens.
//
// POST /api/v1/auth/token with X-API-Key / X-API-Secret returns
// {"token","expires_in","token_type","client"}. The token is cached until
// expires_in - tokenRefreshBuffer and then fetched again; a 401 token_expired
// on any call additionally invalidates the cache so the call is retried with
// a fresh token (see httpClient.do).
type tokenManager struct {
	apiKey     string
	apiSecret  string
	baseURL    string
	httpClient *http.Client
	token      string
	expiresAt  time.Time
	mu         sync.RWMutex
}

// newTokenManager creates a new tokenManager. timeout bounds the auth call
// the same way it bounds business calls (Config.Timeout).
func newTokenManager(apiKey, apiSecret, baseURL string, timeout time.Duration) *tokenManager {
	return &tokenManager{
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		baseURL:    baseURL,
		httpClient: newNoRedirectHTTPClient(timeout),
	}
}

// getToken returns a valid JWT token, refreshing if necessary. ctx is the
// business call's context: its deadline / cancellation also covers the
// POST /api/v1/auth/token the refresh makes.
func (tm *tokenManager) getToken(ctx context.Context) (string, error) {
	tm.mu.RLock()
	if tm.token != "" && time.Now().Before(tm.expiresAt) {
		token := tm.token
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	return tm.refreshToken(ctx)
}

// invalidate drops the cached token so the next getToken fetches a new one.
func (tm *tokenManager) invalidate() {
	tm.mu.Lock()
	tm.token = ""
	tm.expiresAt = time.Time{}
	tm.mu.Unlock()
}

// refreshToken fetches a new JWT token
func (tm *tokenManager) refreshToken(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock
	if tm.token != "" && time.Now().Before(tm.expiresAt) {
		return tm.token, nil
	}

	url := fmt.Sprintf("%s/api/v1/auth/token", tm.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("X-API-Key", tm.apiKey)
	req.Header.Set("X-API-Secret", tm.apiSecret)

	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", redirectError(resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	// 401 invalid credentials / 403 IP not allowed or client inactive, as *APIError.
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("auth request failed: %w", decodeAPIError(resp.StatusCode, respBody))
	}

	var tokResp tokenResponse
	if err := json.Unmarshal(respBody, &tokResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}
	if tokResp.Token == "" {
		return "", fmt.Errorf("auth response did not contain a token")
	}

	lifetime := time.Duration(tokResp.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultTokenLifetime
	}
	if lifetime > tokenRefreshBuffer {
		lifetime -= tokenRefreshBuffer
	} else {
		lifetime /= 2
	}

	tm.token = tokResp.Token
	tm.expiresAt = time.Now().Add(lifetime)

	return tm.token, nil
}

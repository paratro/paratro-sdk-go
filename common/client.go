package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/reefiy/mpc-sdk-go/auth"
)

// Client is the HTTP client for making API requests
type Client struct {
	BaseURL      string
	HTTPClient   *http.Client
	TokenManager *auth.TokenManager
}

// NewClient creates a new API client
func NewClient(baseURL string, tokenManager *auth.TokenManager) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		TokenManager: tokenManager,
	}
}

// APIResponse represents the unified API response structure
type APIResponse struct {
	Code      int             `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	TraceID   string          `json:"trace_id"`
	Timestamp int64           `json:"timestamp"`
	PaginatedData
}

// PaginatedData represents paginated response data
type PaginatedData struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalCount int `json:"total"`
}

// Request makes an HTTP request to the API
func (c *Client) Request(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonData)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Get JWT token
	token, err := c.TokenManager.GetToken()
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Execute request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse API response
	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Check response code
	if apiResp.Code != 200000 {
		return fmt.Errorf("API error: %s (code: %d, trace_id: %s)",
			apiResp.Message, apiResp.Code, apiResp.TraceID)
	}

	// Decode data if result is provided
	if result != nil && len(apiResp.Data) > 0 {
		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("failed to decode response data: %w", err)
		}
	}

	return nil
}

// RequestWithQuery makes an HTTP GET request with query parameters
func (c *Client) RequestWithQuery(path string, params map[string]string, result interface{}) error {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add query parameters
	if params != nil {
		q := req.URL.Query()
		for key, value := range params {
			if value != "" {
				q.Add(key, value)
			}
		}
		req.URL.RawQuery = q.Encode()
	}

	// Get JWT token
	token, err := c.TokenManager.GetToken()
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Execute request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse API response
	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Check response code
	if apiResp.Code != 200000 {
		return fmt.Errorf("API error: %s (code: %d, trace_id: %s)",
			apiResp.Message, apiResp.Code, apiResp.TraceID)
	}

	// Decode data if result is provided
	if result != nil && len(apiResp.Data) > 0 {
		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("failed to decode response data: %w", err)
		}
	}

	return nil
}

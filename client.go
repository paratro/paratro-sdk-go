package paratro

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MPCClient is the main MPC SDK client
type MPCClient struct {
	config       *Config
	tokenManager *tokenManager
	apiClient    *httpClient

	// Services
	Wallet      *service
	Account     *service
	Asset       *service
	Transaction *service
	X402        *service
}

// NewMPCClient creates a new MPC SDK client
func NewMPCClient(apiKey, apiSecret string, config *Config) (*MPCClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("apiKey is required")
	}
	if apiSecret == "" {
		return nil, fmt.Errorf("apiSecret is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	tm := newTokenManager(apiKey, apiSecret, config.BaseURL)
	apiClient := newHTTPClient(config.BaseURL, tm)

	client := &MPCClient{
		config:       config,
		tokenManager: tm,
		apiClient:    apiClient,
		Wallet:       newService(apiClient),
		Account:      newService(apiClient),
		Asset:        newService(apiClient),
		Transaction:  newService(apiClient),
		X402:         newService(apiClient),
	}

	return client, nil
}

// Config returns the client configuration
func (c *MPCClient) Config() *Config {
	return c.config
}

// service handles API operations for a resource
type service struct {
	client *httpClient
}

// newService creates a new service
func newService(client *httpClient) *service {
	return &service{client: client}
}

// httpClient is the internal HTTP client for making API requests
type httpClient struct {
	BaseURL      string
	HTTPClient   *http.Client
	tokenManager *tokenManager
}

// newHTTPClient creates a new internal HTTP client
func newHTTPClient(baseURL string, tm *tokenManager) *httpClient {
	return &httpClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		tokenManager: tm,
	}
}

// ErrorBody represents the API error response
type ErrorBody struct {
	Code    string `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// APIError wraps ErrorBody with HTTP status for the error interface
type APIError struct {
	HTTPStatus int
	ErrorBody
}

// Error implements the error interface
func (e *APIError) Error() string {
	return fmt.Sprintf("API error: %s - %s (type: %s, http_status: %d)",
		e.Code, e.Message, e.Type, e.HTTPStatus)
}

// IsNotFound reports whether the error is a 404 Not Found response.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound
}

// IsRateLimited reports whether the error is a 429 Too Many Requests response.
func IsRateLimited(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusTooManyRequests
}

// IsAuthError reports whether the error is an authentication/authorization error (401 or 403).
func IsAuthError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && (apiErr.HTTPStatus == http.StatusUnauthorized || apiErr.HTTPStatus == http.StatusForbidden)
}

// request makes an HTTP request to the API
func (c *httpClient) request(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonData)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	token, err := c.tokenManager.getToken()
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errBody ErrorBody
		if err := json.Unmarshal(respBody, &errBody); err != nil {
			return &APIError{
				HTTPStatus: resp.StatusCode,
				ErrorBody: ErrorBody{
					Code:    "unknown",
					Message: string(respBody),
				},
			}
		}
		return &APIError{HTTPStatus: resp.StatusCode, ErrorBody: errBody}
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// requestWithQuery makes an HTTP GET request with query parameters
func (c *httpClient) requestWithQuery(ctx context.Context, path string, params map[string]string, result interface{}) error {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if params != nil {
		q := req.URL.Query()
		for key, value := range params {
			if value != "" {
				q.Add(key, value)
			}
		}
		req.URL.RawQuery = q.Encode()
	}

	token, err := c.tokenManager.getToken()
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errBody ErrorBody
		if err := json.Unmarshal(respBody, &errBody); err != nil {
			return &APIError{
				HTTPStatus: resp.StatusCode,
				ErrorBody: ErrorBody{
					Code:    "unknown",
					Message: string(respBody),
				},
			}
		}
		return &APIError{HTTPStatus: resp.StatusCode, ErrorBody: errBody}
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

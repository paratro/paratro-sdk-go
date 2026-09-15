package paratro

import (
	"bytes"
	"context"
	"encoding/json"
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

	timeout := config.timeout()
	tm := newTokenManager(apiKey, apiSecret, config.BaseURL, timeout)
	apiClient := newHTTPClient(config.BaseURL, tm, timeout)

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
func newHTTPClient(baseURL string, tm *tokenManager, timeout time.Duration) *httpClient {
	return &httpClient{
		BaseURL:      baseURL,
		HTTPClient:   newNoRedirectHTTPClient(timeout),
		tokenManager: tm,
	}
}

// newNoRedirectHTTPClient returns an http.Client that never follows redirects:
// credentials and transaction payloads are bound to the configured base URL.
// timeout is Config.Timeout (DefaultTimeout when unset); the per-call context
// deadline applies on top of it.
func newNoRedirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: noRedirectTransport{base: http.DefaultTransport},
	}
}

// noRedirectTransport strips the Location header from 3xx responses. net/http
// parses Location before CheckRedirect runs, so a malformed destination would
// otherwise surface inside the returned error.
type noRedirectTransport struct{ base http.RoundTripper }

func (t noRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Header = resp.Header.Clone()
		resp.Header.Del("Location")
	}
	return resp, err
}

func redirectError(status int) error {
	return &APIError{HTTPStatus: status, ErrorBody: ErrorBody{
		Code: "unexpected_redirect", Type: "transport_error", Message: "API redirects are not followed",
	}}
}

// requestOptions carries per-call knobs collected from RequestOption values.
type requestOptions struct {
	headers map[string]string
}

// RequestOption customises a single API call.
type RequestOption func(*requestOptions)

// WithIdempotencyKey sets the Idempotency-Key header. The gateway honours it on
// POST /api/v1/transactions and POST /api/v1/x402/settle: a repeated POST with
// the same key from the same client within 24 hours returns the cached body of
// the first successful (2xx) response — always with HTTP 200, even when the
// original answer was 202. Callers that rely on Accepted() should therefore
// also look at Status when replaying.
//
// The key is independent of reference_id: reference_id is the business
// reference stored on the transaction (reuse → 400 Duplicate reference_id),
// Idempotency-Key only de-duplicates the HTTP call.
func WithIdempotencyKey(key string) RequestOption {
	return func(o *requestOptions) {
		if key == "" {
			return
		}
		if o.headers == nil {
			o.headers = map[string]string{}
		}
		o.headers["Idempotency-Key"] = key
	}
}

func applyOptions(opts []RequestOption) requestOptions {
	var o requestOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// do sends one API request and decodes the response. It returns the HTTP
// status so callers can tell 200 from 202. On 401 token_expired it refreshes
// the JWT once and replays the request.
func (c *httpClient) do(ctx context.Context, method, path string, query map[string]string, body interface{}, result interface{}, opts ...RequestOption) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}
	options := applyOptions(opts)

	status, err := c.send(ctx, method, path, query, payload, result, options)
	if err == nil || !IsTokenExpired(err) {
		return status, err
	}

	// Token expired between our local expiry estimate and the gateway's clock:
	// drop it, fetch a new one, replay exactly once.
	c.tokenManager.invalidate()
	return c.send(ctx, method, path, query, payload, result, options)
}

func (c *httpClient) send(ctx context.Context, method, path string, query map[string]string, payload []byte, result interface{}, options requestOptions) (int, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	if len(query) > 0 {
		q := req.URL.Query()
		for key, value := range query {
			if value != "" {
				q.Add(key, value)
			}
		}
		req.URL.RawQuery = q.Encode()
	}

	token, err := c.tokenManager.getToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get JWT token: %w", err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range options.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, redirectError(resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return resp.StatusCode, decodeAPIError(resp.StatusCode, respBody)
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return resp.StatusCode, nil
}

// decodeAPIError turns a non-2xx body into *APIError. Bodies that are not the
// gateway's {"code","type","message"} shape are kept verbatim in Message.
func decodeAPIError(status int, respBody []byte) error {
	var errBody ErrorBody
	if err := json.Unmarshal(respBody, &errBody); err != nil || errBody.Code == "" {
		return &APIError{
			HTTPStatus: status,
			ErrorBody: ErrorBody{
				Code:    "unknown",
				Message: string(respBody),
			},
		}
	}
	return &APIError{HTTPStatus: status, ErrorBody: errBody}
}

// request makes a JSON API request without query parameters.
func (c *httpClient) request(ctx context.Context, method, path string, body interface{}, result interface{}, opts ...RequestOption) error {
	_, err := c.do(ctx, method, path, nil, body, result, opts...)
	return err
}

// requestWithQuery makes an HTTP GET request with query parameters.
func (c *httpClient) requestWithQuery(ctx context.Context, path string, params map[string]string, result interface{}) error {
	_, err := c.do(ctx, http.MethodGet, path, params, nil, result)
	return err
}

package paratro

import "time"

// DefaultTimeout is the HTTP timeout used when Config.Timeout is zero.
//
// PROGRAM_CALL / CONTRACT_CALL are synchronous: the gateway keeps the
// connection open while the signing engine signs and broadcasts. The gateway's
// own ceilings (develop, main.go / internal/client / internal/service):
//
//	engine budget                      120s  (x402.sync-signing.timeout-seconds,
//	                                          default DefaultEngineTimeoutSeconds)
//	wait for the engine before a 202   150s  (budget + SyncSettleClientMargin 30s)
//	server WriteTimeout                180s  (the connection is closed after this)
//
// The SDK default sits above the WriteTimeout so the gateway, never the SDK, is
// the side that gives up: a slow engine then ends in a 202 with a tx_id, and
// past 180s the gateway closes the connection itself. A client-side timeout on
// that call has no tx_id and GET /api/v1/transactions cannot filter by
// reference_id (see CreateTransaction). 150s would not do — it is exactly how
// long the gateway waits for the engine before answering 202, and the SDK's
// timer starts earlier than the gateway's.
const DefaultTimeout = 200 * time.Second

// Config holds the configuration for the MPC SDK
type Config struct {
	BaseURL string

	// Timeout bounds every HTTP exchange the SDK makes (connect, request,
	// response), including POST /api/v1/auth/token. Zero means DefaultTimeout.
	//
	// Do not set it below DefaultTimeout for a client that sends PROGRAM_CALL
	// or CONTRACT_CALL; the same applies to the context deadline you pass to
	// CreateTransaction. Shorter deadlines are fine for GET calls and TRANSFER.
	Timeout time.Duration
}

// Sandbox returns configuration for the sandbox environment
func Sandbox() *Config {
	return &Config{
		BaseURL: "https://api-sandbox.paratro.com",
	}
}

// Production returns configuration for the production environment
func Production() *Config {
	return &Config{
		BaseURL: "https://api.paratro.com",
	}
}

// Custom returns a custom configuration with the specified base URL
func Custom(baseURL string) *Config {
	return &Config{
		BaseURL: baseURL,
	}
}

// timeout returns the effective HTTP timeout.
func (c *Config) timeout() time.Duration {
	if c == nil || c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

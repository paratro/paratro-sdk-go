package paratro

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Timeouts. PROGRAM_CALL / CONTRACT_CALL hold the connection while the gateway
// waits for the signing engine; the SDK must not be the side that gives up
// first, because a client-side timeout loses the tx_id.

// Gateway ceilings (paratro-mpc-gateway develop):
const (
	// gatewayEngineBudget: service.DefaultEngineTimeoutSeconds /
	// configs/sandbox_config.yaml x402.sync-signing.timeout-seconds.
	gatewayEngineBudget = 120 * time.Second
	// gatewaySettleClientMargin: internal/client/sync_settle_client.go
	// SyncSettleClientMargin, added to the budget for the gateway→engine HTTP
	// client. budget + margin is how long the gateway waits for the engine on a
	// PROGRAM_CALL before it answers 202 (CONTRACT_CALL: permit 60s+5s, then
	// settle 60s+30s).
	gatewaySettleClientMargin = 30 * time.Second
	// gatewayWriteTimeout: main.go http.Server.WriteTimeout — the gateway closes
	// the connection after this no matter what.
	gatewayWriteTimeout = 180 * time.Second
)

func TestDefaultTimeoutCoversEngineBudget(t *testing.T) {
	// The 202 for a hung engine is written at budget+margin after the gateway
	// started the engine call, which is after the SDK's own timer started; the
	// default must therefore exceed that wait with room to spare, and the
	// clean bound is the WriteTimeout: past it the gateway closes the
	// connection itself, so a client waiting longer never gives up first.
	engineWait := gatewayEngineBudget + gatewaySettleClientMargin
	if DefaultTimeout <= engineWait {
		t.Fatalf("DefaultTimeout %v must exceed the gateway's engine wait %v (budget %v + margin %v) or it clips the 202",
			DefaultTimeout, engineWait, gatewayEngineBudget, gatewaySettleClientMargin)
	}
	if DefaultTimeout <= gatewayWriteTimeout {
		t.Fatalf("DefaultTimeout %v must exceed the gateway WriteTimeout %v so the gateway gives up first", DefaultTimeout, gatewayWriteTimeout)
	}
	for _, cfg := range []*Config{Sandbox(), Production(), Custom("https://gw.example")} {
		c, err := NewMPCClient("k", "s", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.apiClient.HTTPClient.Timeout; got != DefaultTimeout {
			t.Errorf("%s: business http.Client timeout = %v, want %v", cfg.BaseURL, got, DefaultTimeout)
		}
		if got := c.tokenManager.httpClient.Timeout; got != DefaultTimeout {
			t.Errorf("%s: auth http.Client timeout = %v, want %v", cfg.BaseURL, got, DefaultTimeout)
		}
	}

	custom := &Config{BaseURL: "https://gw.example", Timeout: 7 * time.Minute}
	c, err := NewMPCClient("k", "s", custom)
	if err != nil {
		t.Fatal(err)
	}
	if c.apiClient.HTTPClient.Timeout != 7*time.Minute || c.tokenManager.httpClient.Timeout != 7*time.Minute {
		t.Errorf("Config.Timeout not applied: business=%v auth=%v", c.apiClient.HTTPClient.Timeout, c.tokenManager.httpClient.Timeout)
	}
	if (&Config{Timeout: -1}).timeout() != DefaultTimeout || (*Config)(nil).timeout() != DefaultTimeout {
		t.Error("non-positive / nil config must fall back to DefaultTimeout")
	}
}

// TestCreateTransactionSurvivesSlowGateway holds a CONTRACT_CALL for 35s —
// longer than the 30s the 1.7 client hard-coded — and expects the
// BROADCAST answer, not a client-side timeout. Skipped with -short.
func TestCreateTransactionSurvivesSlowGateway(t *testing.T) {
	if testing.Short() {
		t.Skip("35s slow-gateway test; run without -short")
	}
	const hold = 35 * time.Second
	c, _ := contractClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/transactions" || r.Method != http.MethodPost {
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		}
		time.Sleep(hold)
		_, _ = w.Write([]byte(`{"tx_id":"tx-slow","status":"BROADCAST","message":"CONTRACT_CALL broadcast","tx_hash":"0xslow"}`))
	})
	start := time.Now()
	resp, err := c.Transaction.CreateTransaction(context.Background(), minimalContractCall())
	if err != nil {
		t.Fatalf("SDK timed out before the gateway answered (after %v): %v", time.Since(start), err)
	}
	if resp.TxID != "tx-slow" || resp.Status != StatusBroadcast || resp.TxHash != "0xslow" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if time.Since(start) < hold {
		t.Errorf("response arrived after %v, before the %v hold — the fake gateway did not block", time.Since(start), hold)
	}
}

func TestConfigTimeoutIsHonoured(t *testing.T) {
	var reached atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			_, _ = w.Write([]byte(`{"token":"t","expires_in":900}`))
			return
		}
		reached.Add(1)
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`{"tx_id":"late","status":"BROADCAST","message":"m","tx_hash":"0x"}`))
	}))
	defer srv.Close()
	c, err := NewMPCClient("k", "s", &Config{BaseURL: srv.URL, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Transaction.CreateTransaction(context.Background(), minimalContractCall())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected a client-side timeout")
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Errorf("timeout must be a transport error, not *APIError: %v", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("timed out after %v, want ≈200ms", elapsed)
	}
	if reached.Load() != 1 {
		t.Errorf("request reached the gateway %d times, want 1 (no automatic resend)", reached.Load())
	}
}

// TestContextDeadlineCoversTokenRefresh: the caller's context deadline applies
// to the POST /auth/token the SDK makes on its behalf, not only to the business
// request.
func TestContextDeadlineCoversTokenRefresh(t *testing.T) {
	var business atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			_, _ = w.Write([]byte(`{"token":"t","expires_in":900}`))
			return
		}
		business.Add(1)
	}))
	defer srv.Close()
	c, err := NewMPCClient("k", "s", Custom(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Transaction.GetTransaction(ctx, "tx")
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded from the auth call, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to get JWT token") {
		t.Errorf("error should name the auth step: %v", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("auth call ignored the context deadline: returned after %v", elapsed)
	}
	if business.Load() != 0 {
		t.Error("business request sent without a token")
	}
}

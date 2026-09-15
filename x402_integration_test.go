package paratro

import (
	"context"
	"testing"
	"time"
)

// ============ X402 Tests ============
//
// POST /api/v1/x402/sign was retired by the gateway (HTTP 410) and the SDK no
// longer has an X402Sign method; see TestX402SignRemoved in client_contract_test.go.

func TestX402ListSettlements(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	resp, err := client.X402.X402ListSettlements(ctx, &ListX402SettlementsRequest{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("Failed to list x402 settlements: %v", err)
	}

	t.Logf("Found %d x402 settlements (Total: %d, HasMore: %v)", len(resp.Items), resp.Total, resp.HasMore)
	for i, item := range resp.Items {
		if i < 5 {
			t.Logf("  %d. tx_id=%s status=%s amount=%s", i+1, item.TxID, item.Status, item.Amount)
		}
	}
}

func TestX402Verify(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	// Send a minimal payload; expect a validation error from the API.
	_, err := client.X402.X402Verify(ctx, map[string]interface{}{
		"payload": "invalid",
	})
	if err == nil {
		t.Error("Expected error for minimal/invalid verify payload")
	}

	t.Logf("X402 Verify API tested (expected error: %v)", err)
}

func TestX402Settle(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	// Send a minimal payload; expect a validation error from the API.
	_, err := client.X402.X402Settle(ctx, map[string]interface{}{
		"payload": "invalid",
	})
	if err == nil {
		t.Error("Expected error for minimal/invalid settle payload")
	}

	t.Logf("X402 Settle API tested (expected error: %v)", err)
}

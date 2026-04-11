package paratro

import (
	"context"
	"testing"
	"time"
)

// ============ X402 Tests ============

func TestX402Sign(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	// Test with a real sign request; requires a valid from_address in the test account.
	fromAddress := "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	toAddress := "0x000000000000000000000000000000000000dead"

	resp, err := client.X402.X402Sign(ctx, &X402SignRequest{
		FromAddress: fromAddress,
		ToAddress:   toAddress,
		Chain:       "base-sepolia",
		Amount:      "0.01",
		ValidBefore: time.Now().Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		// May fail if from_address is not owned by the test account; log and continue.
		t.Logf("X402Sign returned error (may be expected): %v", err)
		return
	}

	if resp.AuthID == "" {
		t.Error("Expected auth_id to be set")
	}

	t.Logf("X402 Sign: auth_id=%s tx_id=%s status=%s", resp.AuthID, resp.TxID, resp.Status)
}

func TestX402ListAuthorizations(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	resp, err := client.X402.X402ListAuthorizations(ctx, 1, 20)
	if err != nil {
		t.Fatalf("Failed to list x402 authorizations: %v", err)
	}

	t.Logf("Found %d x402 authorizations (Total: %d, HasMore: %v)", len(resp.Items), resp.Total, resp.HasMore)
	for i, auth := range resp.Items {
		if i < 5 {
			t.Logf("  %d. auth_id=%s status=%s amount=%s", i+1, auth.AuthID, auth.Status, auth.Amount)
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

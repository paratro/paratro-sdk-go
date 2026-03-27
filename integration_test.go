package paratro

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func getTestClient(t *testing.T) *MPCClient {
	apiKey := os.Getenv("MPC_API_KEY")
	apiSecret := os.Getenv("MPC_API_SECRET")

	if apiKey == "" || apiSecret == "" {
		t.Skip("MPC_API_KEY and MPC_API_SECRET must be set")
	}

	client, err := NewMPCClient(apiKey, apiSecret, Sandbox())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	return client
}

func skipIntegration(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}
}

// Shared state across tests
var (
	activeWalletID string // from MPC_TEST_WALLET_ID env, used for account/asset tests
	testAccountID  string
	testAssetID    string
)

func init() {
	// Load .env file if present
	if f, err := os.Open(".env"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				if os.Getenv(k) == "" {
					os.Setenv(k, v)
				}
			}
		}
	}

	activeWalletID = os.Getenv("MPC_TEST_WALLET_ID")
}

// ============ Wallet Tests ============

func TestWalletCreate(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	w, err := client.Wallet.CreateWallet(ctx, &CreateWalletRequest{
		WalletName:  "SDK Test Wallet",
		Description: "Integration test wallet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	if w.WalletID == "" {
		t.Error("Expected wallet ID to be set")
	}

	t.Logf("Created wallet: %s (status: %s)", w.WalletID, w.Status)
}

func TestWalletGet(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	if activeWalletID == "" {
		t.Skip("No test wallet available (TestWalletCreate may have failed)")
	}

	time.Sleep(500 * time.Millisecond)

	w, err := client.Wallet.GetWallet(ctx, activeWalletID)
	if err != nil {
		t.Fatalf("Failed to get wallet: %v", err)
	}

	if w.WalletID != activeWalletID {
		t.Errorf("Expected wallet ID %s, got %s", activeWalletID, w.WalletID)
	}

	t.Logf("Retrieved wallet: %s (status: %s)", w.WalletID, w.Status)
}

func TestWalletList(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	resp, err := client.Wallet.ListWallets(ctx, &ListWalletsRequest{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list wallets: %v", err)
	}

	t.Logf("Found %d wallets (Total: %d, HasMore: %v)", len(resp.Items), resp.Total, resp.HasMore)
}

// ============ Account Tests ============

func TestAccountCreate(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	if activeWalletID == "" {
		t.Skip("MPC_TEST_WALLET_ID not set")
	}

	time.Sleep(500 * time.Millisecond)

	a, err := client.Account.CreateAccount(ctx, &CreateAccountRequest{
		WalletID: activeWalletID,
		Chain:    "ethereum",
		Label:    "SDK Test Account",
	})
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	if a.AccountID == "" {
		t.Error("Expected account ID to be set")
	}

	testAccountID = a.AccountID
	t.Logf("Created account: %s (Address: %s)", a.AccountID, a.Address)
}

func TestAccountGet(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	if testAccountID == "" {
		t.Skip("No test account available (TestAccountCreate may have been skipped)")
	}

	time.Sleep(500 * time.Millisecond)

	a, err := client.Account.GetAccount(ctx, testAccountID)
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	if a.AccountID != testAccountID {
		t.Errorf("Expected account ID %s, got %s", testAccountID, a.AccountID)
	}

	t.Logf("Retrieved account: %s", a.AccountID)
}

func TestAccountList(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	resp, err := client.Account.ListAccounts(ctx, &ListAccountsRequest{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list accounts: %v", err)
	}

	t.Logf("Found %d accounts (Total: %d, HasMore: %v)", len(resp.Items), resp.Total, resp.HasMore)
}

// ============ Asset Tests ============

func TestAssetCreate(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	if testAccountID == "" {
		t.Skip("No test account available (TestAccountCreate may have been skipped)")
	}

	time.Sleep(500 * time.Millisecond)

	createdAsset, err := client.Asset.CreateAsset(ctx, &CreateAssetRequest{
		AccountID: testAccountID,
		Symbol:    "USDC",
		Chain:     "ethereum",
	})
	if err != nil {
		t.Fatalf("Failed to create asset: %v", err)
	}

	if createdAsset.AssetID == "" {
		t.Error("Expected asset ID to be set")
	}

	testAssetID = createdAsset.AssetID
	t.Logf("Created asset: %s (%s)", createdAsset.AssetID, createdAsset.Symbol)
}

func TestAssetGet(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	if testAssetID == "" {
		t.Skip("No test asset available (TestAssetCreate may have been skipped)")
	}

	time.Sleep(500 * time.Millisecond)

	a, err := client.Asset.GetAsset(ctx, testAssetID)
	if err != nil {
		t.Fatalf("Failed to get asset: %v", err)
	}

	if a.AssetID != testAssetID {
		t.Errorf("Expected asset ID %s, got %s", testAssetID, a.AssetID)
	}

	t.Logf("Retrieved asset: %s (%s)", a.AssetID, a.Symbol)
}

func TestAssetList(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	resp, err := client.Asset.ListAssets(ctx, &ListAssetsRequest{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list assets: %v", err)
	}

	t.Logf("Found %d assets (Total: %d, HasMore: %v)", len(resp.Items), resp.Total, resp.HasMore)
	for i, ast := range resp.Items {
		t.Logf("  %d. %s (%s)", i+1, ast.Symbol, ast.Name)
	}
}

// ============ Transaction Tests ============

func TestTransactionGet(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	_, err := client.Transaction.GetTransaction(ctx, "non-existent-tx-id")
	if err == nil {
		t.Error("Expected error for non-existent transaction")
	}

	t.Logf("Transaction Get API tested (expected error: %v)", err)
}

func TestTransactionList(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	resp, err := client.Transaction.ListTransactions(ctx, &ListTransactionsRequest{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list transactions: %v", err)
	}

	t.Logf("Found %d transactions (Total: %d, HasMore: %v)", len(resp.Items), resp.Total, resp.HasMore)
	for i, tx := range resp.Items {
		if i < 5 {
			t.Logf("  %d. %s %s (%s)", i+1, tx.Amount, tx.TokenSymbol, tx.Status)
		}
	}
}

func TestTransactionListByWallet(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	if activeWalletID == "" {
		t.Skip("No test wallet available")
	}

	time.Sleep(500 * time.Millisecond)

	resp, err := client.Transaction.ListTransactions(ctx, &ListTransactionsRequest{
		WalletID: activeWalletID,
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list transactions: %v", err)
	}

	t.Logf("Found %d transactions for wallet %s", len(resp.Items), activeWalletID)
}

// ============ Transfer Tests ============

func TestCreateTransfer(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)
	ctx := context.Background()

	time.Sleep(500 * time.Millisecond)

	// Test error case with invalid data
	_, err := client.Transaction.CreateTransfer(ctx, &CreateTransferRequest{
		FromAddress: "0xinvalid",
		ToAddress:   "0xinvalid",
		Chain:       "ethereum",
		TokenSymbol: "USDT",
		Amount:      "1.0",
	})
	if err == nil {
		t.Error("Expected error for invalid transfer request")
	}

	t.Logf("Transfer API tested (expected error: %v)", err)
}

// ============ Authentication Tests ============

func TestLogout(t *testing.T) {
	skipIntegration(t)
	client := getTestClient(t)

	time.Sleep(500 * time.Millisecond)

	err := client.Logout()
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}

	t.Logf("Logout successful")
}

// ============ Version Tests ============

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Expected version to be set")
	}
	t.Logf("SDK Version: %s", Version)
}

// ============ Client Tests ============

func TestNewMPCClientValidation(t *testing.T) {
	_, err := NewMPCClient("", "secret", Sandbox())
	if err == nil {
		t.Error("Expected error for empty apiKey")
	}

	_, err = NewMPCClient("key", "", Sandbox())
	if err == nil {
		t.Error("Expected error for empty apiSecret")
	}

	_, err = NewMPCClient("key", "secret", nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

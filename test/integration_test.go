package test

import (
	"context"
	"fmt"
	"os"
	"testing"

	mpcsdk "github.com/reefiy/mpc-sdk-go"
	"github.com/reefiy/mpc-sdk-go/account"
	"github.com/reefiy/mpc-sdk-go/asset"
	"github.com/reefiy/mpc-sdk-go/configuration"
	"github.com/reefiy/mpc-sdk-go/transaction"
	"github.com/reefiy/mpc-sdk-go/wallet"
)

func getTestClient(t *testing.T) *mpcsdk.Client {
	apiKey := os.Getenv("MPC_API_KEY")
	apiSecret := os.Getenv("MPC_API_SECRET")

	if apiKey == "" || apiSecret == "" {
		t.Skip("MPC_API_KEY and MPC_API_SECRET must be set")
	}

	client, err := mpcsdk.NewClient(apiKey, apiSecret, configuration.Sandbox())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	return client
}

// ============ Wallet Tests ============

func TestWalletCreate(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	req := &wallet.CreateWalletRequest{
		WalletName:  "Test Wallet",
		Description: "Integration test wallet",
		Chain:       "ETH",
		Network:     "mainnet",
	}

	w, err := client.Wallet.Create(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	if w.WalletID == "" {
		t.Error("Expected wallet ID to be set")
	}

	t.Logf("✓ Created wallet: %s", w.WalletID)
}

func TestWalletGet(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// First create a wallet
	createReq := &wallet.CreateWalletRequest{
		WalletName: "Test Get Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	}

	created, err := client.Wallet.Create(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	// Now get it
	w, err := client.Wallet.Get(ctx, created.WalletID)
	if err != nil {
		t.Fatalf("Failed to get wallet: %v", err)
	}

	if w.WalletID != created.WalletID {
		t.Errorf("Expected wallet ID %s, got %s", created.WalletID, w.WalletID)
	}

	t.Logf("✓ Retrieved wallet: %s", w.WalletID)
}

func TestWalletList(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	req := &wallet.ListWalletsRequest{
		Page:     1,
		PageSize: 20,
	}

	resp, err := client.Wallet.List(ctx, req)
	if err != nil {
		t.Fatalf("Failed to list wallets: %v", err)
	}

	t.Logf("✓ Found %d wallets", len(resp.Items))
}

// ============ Account Tests ============

func TestAccountCreate(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// First create a wallet
	walletReq := &wallet.CreateWalletRequest{
		WalletName: "Test Account Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	}

	w, err := client.Wallet.Create(ctx, walletReq)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	// Create account
	accountReq := &account.CreateAccountRequest{
		WalletID:    w.WalletID,
		Chain:       "ethereum",
		Network:     "mainnet",
		Label:       "Test Account",
		AccountType: "EOA",
	}

	a, err := client.Account.Create(ctx, accountReq)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	if a.AccountID == "" {
		t.Error("Expected account ID to be set")
	}
	if a.Address == "" {
		t.Error("Expected address to be set")
	}

	t.Logf("✓ Created account: %s (Address: %s)", a.AccountID, a.Address)
}

func TestAccountGet(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Create wallet and account
	w, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
		WalletName: "Test Account Get Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	created, err := client.Account.Create(ctx, &account.CreateAccountRequest{
		WalletID: w.WalletID,
		Chain:    "ethereum",
		Network:  "mainnet",
		Label:    "Test Account",
	})
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Get account
	a, err := client.Account.Get(ctx, created.AccountID)
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	if a.AccountID != created.AccountID {
		t.Errorf("Expected account ID %s, got %s", created.AccountID, a.AccountID)
	}

	t.Logf("✓ Retrieved account: %s", a.AccountID)
}

func TestAccountList(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Create wallet
	w, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
		WalletName: "Test Account List Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	// Create some accounts
	for i := 1; i <= 3; i++ {
		_, err := client.Account.Create(ctx, &account.CreateAccountRequest{
			WalletID: w.WalletID,
			Chain:    "ethereum",
			Network:  "mainnet",
			Label:    fmt.Sprintf("Test Account %d", i),
		})
		if err != nil {
			t.Fatalf("Failed to create account %d: %v", i, err)
		}
	}

	// List accounts
	resp, err := client.Account.List(ctx, &account.ListAccountsRequest{
		WalletID: w.WalletID,
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list accounts: %v", err)
	}

	if len(resp.Items) < 3 {
		t.Errorf("Expected at least 3 accounts, got %d", len(resp.Items))
	}

	t.Logf("✓ Found %d accounts (Total: %d)", len(resp.Items), resp.TotalCount)
}

// ============ Asset Tests ============

func TestAssetCreate(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Create wallet and account
	w, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
		WalletName: "Test Asset Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	a, err := client.Account.Create(ctx, &account.CreateAccountRequest{
		WalletID: w.WalletID,
		Chain:    "ethereum",
		Network:  "mainnet",
		Label:    "Test Account",
	})
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Create asset
	assetReq := &asset.CreateAssetRequest{
		WalletID:        w.WalletID,
		AccountID:       a.AccountID,
		Chain:           "ETH",
		Network:         "mainnet",
		Symbol:          "USDC",
		Name:            "USD Coin",
		AssetType:       "ERC20",
		ContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		Decimals:        6,
	}

	createdAsset, err := client.Asset.Create(ctx, assetReq)
	if err != nil {
		t.Fatalf("Failed to create asset: %v", err)
	}

	if createdAsset.AssetID == "" {
		t.Error("Expected asset ID to be set")
	}

	t.Logf("✓ Created asset: %s (%s)", createdAsset.AssetID, createdAsset.Symbol)
}

func TestAssetGet(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Create wallet, account and asset
	w, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
		WalletName: "Test Asset Get Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	a, err := client.Account.Create(ctx, &account.CreateAccountRequest{
		WalletID: w.WalletID,
		Chain:    "ethereum",
		Network:  "mainnet",
		Label:    "Test Account",
	})
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	created, err := client.Asset.Create(ctx, &asset.CreateAssetRequest{
		WalletID:        w.WalletID,
		AccountID:       a.AccountID,
		Chain:           "ETH",
		Network:         "mainnet",
		Symbol:          "USDT",
		Name:            "Tether USD",
		AssetType:       "ERC20",
		ContractAddress: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
		Decimals:        6,
	})
	if err != nil {
		t.Fatalf("Failed to create asset: %v", err)
	}

	// Get asset
	retrievedAsset, err := client.Asset.Get(ctx, created.AssetID)
	if err != nil {
		t.Fatalf("Failed to get asset: %v", err)
	}

	if retrievedAsset.AssetID != created.AssetID {
		t.Errorf("Expected asset ID %s, got %s", created.AssetID, retrievedAsset.AssetID)
	}

	t.Logf("✓ Retrieved asset: %s (%s)", retrievedAsset.AssetID, retrievedAsset.Symbol)
}

func TestAssetList(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Create wallet and account
	w, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
		WalletName: "Test Asset List Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	a, err := client.Account.Create(ctx, &account.CreateAccountRequest{
		WalletID: w.WalletID,
		Chain:    "ethereum",
		Network:  "mainnet",
		Label:    "Test Account",
	})
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Create multiple assets
	tokens := []struct {
		Symbol   string
		Name     string
		Contract string
	}{
		{"USDC", "USD Coin", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{"USDT", "Tether USD", "0xdAC17F958D2ee523a2206206994597C13D831ec7"},
		{"DAI", "Dai Stablecoin", "0x6B175474E89094C44Da98b954EedeAC495271d0F"},
	}

	for _, token := range tokens {
		_, err := client.Asset.Create(ctx, &asset.CreateAssetRequest{
			WalletID:        w.WalletID,
			AccountID:       a.AccountID,
			Chain:           "ETH",
			Network:         "mainnet",
			Symbol:          token.Symbol,
			Name:            token.Name,
			AssetType:       "ERC20",
			ContractAddress: token.Contract,
			Decimals:        18,
		})
		if err != nil {
			t.Fatalf("Failed to create asset %s: %v", token.Symbol, err)
		}
	}

	// List assets
	resp, err := client.Asset.List(ctx, &asset.ListAssetsRequest{
		AccountID: a.AccountID,
		Page:      1,
		PageSize:  20,
	})
	if err != nil {
		t.Fatalf("Failed to list assets: %v", err)
	}

	if len(resp.Items) < 3 {
		t.Errorf("Expected at least 3 assets, got %d", len(resp.Items))
	}

	t.Logf("✓ Found %d assets (Total: %d)", len(resp.Items), resp.TotalCount)
	for i, ast := range resp.Items {
		t.Logf("  %d. %s (%s)", i+1, ast.Symbol, ast.Name)
	}
}

// ============ Transaction Tests ============

func TestTransactionGet(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Note: This test requires a valid transaction ID from the system
	// For now, we'll test the error case
	_, err := client.Transaction.Get(ctx, "non-existent-tx-id")
	if err == nil {
		t.Error("Expected error for non-existent transaction")
	}

	t.Logf("✓ Transaction Get API tested (expected error: %v)", err)
}

func TestTransactionList(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// List all transactions
	resp, err := client.Transaction.List(ctx, &transaction.ListTransactionsRequest{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list transactions: %v", err)
	}

	t.Logf("✓ Found %d transactions (Total: %d)", len(resp.Items), resp.TotalCount)
	for i, tx := range resp.Items {
		if i < 5 { // Show first 5
			t.Logf("  %d. %s - %s %s (%s)", i+1, tx.TxHash[:10]+"...", tx.Amount, tx.Chain, tx.Status)
		}
	}
}

func TestTransactionListByWallet(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)
	ctx := context.Background()

	// Create a wallet for filtering
	w, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
		WalletName: "Test Transaction List Wallet",
		Chain:      "ETH",
		Network:    "mainnet",
	})
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	// List transactions for this wallet
	resp, err := client.Transaction.List(ctx, &transaction.ListTransactionsRequest{
		WalletID: w.WalletID,
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Failed to list transactions: %v", err)
	}

	t.Logf("✓ Found %d transactions for wallet %s", len(resp.Items), w.WalletID)
}

// ============ Authentication Tests ============

func TestLogout(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests")
	}

	client := getTestClient(t)

	// Logout
	err := client.Logout()
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}

	t.Logf("✓ Logout successful")
}

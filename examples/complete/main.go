// Command complete exercises every public endpoint of the Paratro Go SDK
// against a live environment. It is meant as an end-to-end smoke test.
//
// Usage:
//
//	export PARATRO_API_KEY=ak_live_...
//	export PARATRO_API_SECRET=sk_live_...
//	export PARATRO_WALLET_ID=<wallet-uuid>
//	export PARATRO_ENV=production   # or sandbox (default)
//	go run ./examples/complete
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	paratro "github.com/paratro/paratro-sdk-go"
)

func brief(v interface{}) string {
	b, _ := json.Marshal(v)
	s := string(b)
	if len(s) > 320 {
		s = s[:320] + " …"
	}
	return s
}

func main() {
	apiKey := os.Getenv("PARATRO_API_KEY")
	apiSecret := os.Getenv("PARATRO_API_SECRET")
	walletID := os.Getenv("PARATRO_WALLET_ID")
	if apiKey == "" || apiSecret == "" || walletID == "" {
		fmt.Println("set PARATRO_API_KEY / PARATRO_API_SECRET / PARATRO_WALLET_ID")
		os.Exit(1)
	}

	cfg := paratro.Sandbox()
	if os.Getenv("PARATRO_ENV") == "production" {
		cfg = paratro.Production()
	}
	fmt.Printf("═══ Paratro SDK 全接口测试 → %s ═══\n\n", cfg.BaseURL)

	client, err := paratro.NewMPCClient(apiKey, apiSecret, cfg)
	if err != nil {
		fmt.Println("client init:", err)
		os.Exit(1)
	}
	ctx := context.Background()

	pass, fail := 0, 0
	step := func(name string, fn func() (interface{}, error)) interface{} {
		res, err := fn()
		if err != nil {
			fail++
			fmt.Printf("❌ %-20s %v\n", name, err)
			return nil
		}
		pass++
		fmt.Printf("✅ %-20s %s\n", name, brief(res))
		return res
	}

	// ── Wallet ──
	step("GetWallet", func() (interface{}, error) { return client.Wallet.GetWallet(ctx, walletID) })
	step("ListWallets", func() (interface{}, error) {
		return client.Wallet.ListWallets(ctx, &paratro.ListWalletsRequest{Page: 1, PageSize: 10})
	})
	step("CreateWallet", func() (interface{}, error) {
		return client.Wallet.CreateWallet(ctx, &paratro.CreateWalletRequest{WalletName: "sdk-smoke-test", Description: "created by SDK complete example"})
	})

	// ── Account ──
	step("ListAccounts", func() (interface{}, error) {
		return client.Account.ListAccounts(ctx, &paratro.ListAccountsRequest{WalletID: walletID, Page: 1, PageSize: 10})
	})
	var accountID string
	if a := step("CreateAccount", func() (interface{}, error) {
		return client.Account.CreateAccount(ctx, &paratro.CreateAccountRequest{WalletID: walletID, Chain: "ethereum", Label: "sdk-smoke-acct"})
	}); a != nil {
		if acc, ok := a.(*paratro.Account); ok && acc != nil {
			accountID = acc.AccountID
		}
	}
	if accountID != "" {
		step("GetAccount", func() (interface{}, error) { return client.Account.GetAccount(ctx, accountID) })
	}

	// ── Asset ──
	if accountID != "" {
		step("CreateAsset", func() (interface{}, error) {
			return client.Asset.CreateAsset(ctx, &paratro.CreateAssetRequest{AccountID: accountID, Symbol: "ETH", Chain: "ethereum"})
		})
	}
	step("ListAssets", func() (interface{}, error) {
		return client.Asset.ListAssets(ctx, &paratro.ListAssetsRequest{AccountID: accountID, Page: 1, PageSize: 10})
	})

	// ── Transaction ──
	step("ListTransactions", func() (interface{}, error) {
		return client.Transaction.ListTransactions(ctx, &paratro.ListTransactionsRequest{WalletID: walletID, Page: 1, PageSize: 10})
	})

	// ── Transfer (wallet is empty; this exercises the endpoint/validation path) ──
	step("CreateTransfer", func() (interface{}, error) {
		return client.Wallet.CreateTransfer(ctx, &paratro.CreateTransferRequest{
			FromAddress: "0x0000000000000000000000000000000000000000",
			ToAddress:   "0x0000000000000000000000000000000000000001",
			Chain:       "ethereum",
			TokenSymbol: "ETH",
			Amount:      "0.0001",
			Memo:        "sdk-smoke-transfer",
		})
	})

	fmt.Printf("\n═══ 结果: ✅ %d 通过 / ❌ %d 失败 ═══\n", pass, fail)
}

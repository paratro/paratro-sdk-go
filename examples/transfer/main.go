// Command transfer exercises the full transfer flow on Polygon:
// create a polygon account → add POL asset → TRANSFER via POST /api/v1/transactions.
// The wallet is empty, so this validates the endpoint / balance path end-to-end.
//
//	export PARATRO_API_KEY=... PARATRO_API_SECRET=... PARATRO_WALLET_ID=...
//	export PARATRO_ENV=production
//	export PARATRO_TO_ADDR=0xCBe91E9e6A824Aee1B96628eD721ADf225122BFA
//	go run ./examples/transfer
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	paratro "github.com/paratro/paratro-sdk-go"
)

func pretty(v interface{}) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }

func main() {
	apiKey := os.Getenv("PARATRO_API_KEY")
	apiSecret := os.Getenv("PARATRO_API_SECRET")
	walletID := os.Getenv("PARATRO_WALLET_ID")
	toAddr := os.Getenv("PARATRO_TO_ADDR")
	if toAddr == "" {
		toAddr = "0xCBe91E9e6A824Aee1B96628eD721ADf225122BFA"
	}

	cfg := paratro.Sandbox()
	if os.Getenv("PARATRO_ENV") == "production" {
		cfg = paratro.Production()
	}
	client, err := paratro.NewMPCClient(apiKey, apiSecret, cfg)
	if err != nil {
		fmt.Println("client init:", err)
		os.Exit(1)
	}
	ctx := context.Background()
	fmt.Printf("═══ POL 转账测试 → %s ═══\n\n", cfg.BaseURL)

	// 1. 创建 polygon 账户
	acct, err := client.Account.CreateAccount(ctx, &paratro.CreateAccountRequest{
		WalletID: walletID, Chain: "polygon", Label: "pol-transfer-test",
	})
	if err != nil {
		fmt.Println("① CreateAccount(polygon) ❌", err)
		os.Exit(1)
	}
	fmt.Printf("① polygon 账户创建 ✅  address=%s\n", acct.Address)

	// 2. 添加 POL 资产
	asset, err := client.Asset.CreateAsset(ctx, &paratro.CreateAssetRequest{
		AccountID: acct.AccountID, Symbol: "POL", Chain: "polygon",
	})
	if err != nil {
		fmt.Println("② CreateAsset(POL) ❌", err)
	} else {
		fmt.Printf("② POL 资产添加 ✅  asset_id=%s\n", asset.AssetID)
	}

	// 3. 发起转账 POL → 目标地址（统一入口 POST /api/v1/transactions, operation=TRANSFER）
	fmt.Printf("\n③ CreateTransaction(TRANSFER): %s → %s  (0.1 POL / polygon)\n", acct.Address, toAddr)
	resp, err := client.Transaction.CreateTransaction(ctx, &paratro.TransferRequest{
		FromAddress: acct.Address,
		ToAddress:   toAddr,
		Chain:       "polygon",
		TokenSymbol: "POL",
		Amount:      "0.1",
		Memo:        "sdk pol transfer test",
		ReferenceID: fmt.Sprintf("sdk-pol-%d", time.Now().UnixNano()),
	})
	if err != nil {
		switch {
		case paratro.IsInsufficientBalance(err):
			fmt.Println("   反应 ❌ 余额不足:", err)
		case paratro.IsNotFound(err):
			fmt.Println("   反应 ❌ 地址/资产不属于本客户或未入账:", err)
		default:
			fmt.Println("   反应 ❌:", err)
		}
		return
	}
	// TRANSFER 是异步签名：200 + PENDING，后续用 GetTransaction / webhook 跟进。
	fmt.Println("   反应 ✅:\n" + pretty(resp))

	// 4. 查一次状态
	tx, err := client.Transaction.GetTransaction(ctx, resp.TxID)
	if err != nil {
		fmt.Println("④ GetTransaction ❌", err)
		return
	}
	fmt.Printf("④ GetTransaction ✅  status=%s tx_hash=%s\n", tx.Status, tx.TxHash)
}

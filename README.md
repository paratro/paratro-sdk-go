# Paratro MPC Wallet Gateway Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/paratro/paratro-sdk-go.svg)](https://pkg.go.dev/github.com/paratro/paratro-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/paratro/paratro-sdk-go)](https://goreportcard.com/report/github.com/paratro/paratro-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Go SDK for Paratro MPC Wallet Gateway - A comprehensive Multi-Party Computation wallet management platform.

## Features

- MPC Wallets - Create and manage MPC wallets with enhanced security
- Multi-Chain Support - Ethereum, BSC, Polygon, Avalanche, Arbitrum, Optimism, Tron, Bitcoin, Solana
- Account Management - Create and manage multiple accounts per wallet
- Asset Management - Support for native tokens and ERC20/TRC20 tokens
- Transfer - Send funds to external addresses with automatic asset resolution
- Transaction Tracking - Complete transaction history and status tracking
- Secure - Built-in JWT authentication with automatic token management
- Webhook - HMAC-SHA256 signed webhook notifications for incoming transactions

## Installation

```bash
go get github.com/paratro/paratro-sdk-go@latest
```

**Requirements**: Go 1.21 or higher

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    paratro "github.com/paratro/paratro-sdk-go"
)

func main() {
    client, err := paratro.NewMPCClient(
        "your-api-key",
        "your-api-secret",
        paratro.Sandbox(),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Logout()

    ctx := context.Background()

    // 1. Create wallet
    wallet, err := client.Wallet.CreateWallet(ctx, &paratro.CreateWalletRequest{
        WalletName:  "My Wallet",
        Description: "Primary wallet",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Wallet ID: %s\n", wallet.WalletID)

    // 2. Create account
    account, err := client.Account.CreateAccount(ctx, &paratro.CreateAccountRequest{
        WalletID: wallet.WalletID,
        Chain:    "ethereum",
        Network:  "mainnet",
        Label:    "Deposit Account",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Account: %s (%s)\n", account.AccountID, account.Address)

    // 3. Add asset
    asset, err := client.Asset.CreateAsset(ctx, &paratro.CreateAssetRequest{
        AccountID: account.AccountID,
        Symbol:    "USDT",
        Chain:     "ethereum",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Asset: %s (%s)\n", asset.AssetID, asset.Symbol)

    // 4. Create transfer
    transfer, err := client.Transaction.CreateTransfer(ctx, &paratro.CreateTransferRequest{
        FromAddress: account.Address,
        ToAddress:   "0xbbbb...",
        Chain:       "ethereum",
        TokenSymbol: "USDT",
        Amount:      "10.5",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Transfer: %s (%s)\n", transfer.TxID, transfer.Status)

    // 5. List transactions
    txList, err := client.Transaction.ListTransactions(ctx, &paratro.ListTransactionsRequest{
        WalletID: wallet.WalletID,
        Page:     1,
        PageSize: 20,
    })
    if err != nil {
        log.Fatal(err)
    }
    for _, tx := range txList.Items {
        fmt.Printf("TX: %s %s %s (%s)\n", tx.TxHash, tx.Amount, tx.TokenSymbol, tx.Status)
    }
}
```

## Configuration

```go
// Sandbox (for testing)
client, err := paratro.NewMPCClient(apiKey, apiSecret, paratro.Sandbox())

// Production
client, err := paratro.NewMPCClient(apiKey, apiSecret, paratro.Production())

// Custom environment
client, err := paratro.NewMPCClient(apiKey, apiSecret, paratro.Custom("https://your-api.example.com"))
```

## Error Handling

The SDK returns structured `*paratro.APIError` for API failures, with convenience helpers:

```go
wallet, err := client.Wallet.GetWallet(ctx, walletID)
if err != nil {
    if paratro.IsNotFound(err) {
        log.Println("Wallet not found")
    } else if paratro.IsAuthError(err) {
        log.Println("Authentication failed")
    } else if paratro.IsRateLimited(err) {
        log.Println("Rate limited, retry later")
    }
}
```

See [Error Handling Guide](docs/error-handling.md) for detailed usage.

## Documentation

- [API Reference](docs/api-reference.md) - Complete endpoint documentation with request/response formats
- [Webhook Reference](docs/webhook-reference.md) - Webhook signature verification and integration guide
- [Error Handling](docs/error-handling.md) - Error types and handling patterns

## Development

### Project Structure

```
paratro-sdk-go/
├── client.go           # HTTP client, error types, service infrastructure
├── config.go           # Environment configuration
├── token.go            # JWT token management
├── wallet.go           # Wallet API
├── account.go          # Account API
├── asset.go            # Asset API
├── transaction.go      # Transaction API
├── transfer.go         # Transfer API
├── version.go          # SDK version
├── integration_test.go # Integration tests
└── docs/               # Documentation
```

### Build & Test

```bash
go build ./...
go vet ./...
go test -v -count=1 ./...
```

## Support

- Email: support@paratro.com
- Documentation: https://docs.paratro.com
- Issues: https://github.com/paratro/paratro-sdk-go/issues

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

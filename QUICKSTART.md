# Quick Start Guide

This guide will help you get started with the Reefiy MPC Wallet Gateway Go SDK in minutes.

## Installation

```bash
go get github.com/reefiy/mpc-sdk-go@latest
```

## Basic Setup

```go
package main

import (
    "context"
    "log"
    
    mpcsdk "github.com/reefiy/mpc-sdk-go"
    "github.com/reefiy/mpc-sdk-go/configuration"
    "github.com/reefiy/mpc-sdk-go/wallet"
)

func main() {
    // Create client
    client, err := mpcsdk.NewClient(
        "your-client-id",
        "your-client-secret",
        configuration.Sandbox(), // or configuration.Production()
    )
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    
    // Now you're ready to use the SDK!
}
```

## Common Operations

### 1. Create a Wallet

```go
myWallet, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
    UserID:     "user-123",
    WalletType: "MPC",
    ChainType:  "ETH",
    WalletName: "My Ethereum Wallet",
})
```

### 2. Get Wallet Balance

```go
balance, err := client.Wallet.GetBalance(ctx, myWallet.WalletID)
```

### 3. Send a Transaction

```go
tx, err := client.Transaction.Create(ctx, &transaction.CreateTransactionRequest{
    WalletID:  myWallet.WalletID,
    ToAddress: "0x1234567890abcdef1234567890abcdef12345678",
    Amount:    "0.1",
    ChainType: "ETH",
})
```

### 4. Check Transaction Status

```go
txDetails, err := client.Transaction.Get(ctx, tx.TransactionID)
```

## Examples

Check the `examples/` directory for more comprehensive examples:

```bash
cd examples
go run main.go
```

## Environment Variables

For production use, set environment variables:

```bash
export MPC_CLIENT_ID="your-client-id"
export MPC_CLIENT_SECRET="your-client-secret"
```

## Next Steps

- Read the full [README.md](README.md) for detailed API documentation
- Check out [examples/main.go](examples/main.go) for complete examples
- See [CONTRIBUTING.md](CONTRIBUTING.md) if you want to contribute

## Support

- 📧 Email: support@reefiy.com
- 📚 Documentation: https://docs.reefiy.com
- 🐛 Issues: https://github.com/reefiy/mpc-sdk-go/issues


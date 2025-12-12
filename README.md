# Reefiy MPC Wallet Gateway Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/reefiy/mpc-sdk-go.svg)](https://pkg.go.dev/github.com/reefiy/mpc-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/reefiy/mpc-sdk-go)](https://goreportcard.com/report/github.com/reefiy/mpc-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Go SDK for Reefiy MPC Wallet Gateway - A comprehensive Multi-Party Computation wallet management platform.

## Features

* 🚀 **Easy Integration** - Simple and intuitive API
* 🔐 **MPC Wallets** - Create and manage MPC wallets with enhanced security
* 💰 **Multi-Chain Support** - Support for ETH, TRX, BTC, and more
* 🏦 **Account Management** - Create and manage multiple accounts per wallet
* 💎 **Asset Management** - Support for native tokens and ERC20/TRC20 tokens
* 📊 **Transaction Tracking** - Complete transaction history and status tracking
* 🔒 **Secure** - Built-in JWT authentication with automatic token management
* 🌍 **Multi-Environment** - Support for Sandbox and Production environments

## Installation

```bash
go get github.com/reefiy/mpc-sdk-go@latest
```

**Requirements**: Go 1.19 or higher

## Quick Start

### Initialize the SDK

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
    // Create client with API Key and Secret
    client, err := mpcsdk.NewClient(
        "ak_test_550e8400e29b41d4a716446655440000", // API Key
        "test_secret_123456",                        // API Secret
        configuration.Sandbox(),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Logout()

    ctx := context.Background()

    // Your code here...
}
```

### Create an MPC Wallet

```go
myWallet, err := client.Wallet.Create(ctx, &wallet.CreateWalletRequest{
    WalletName:  "my primary wallet",
    Description: "c",
    Chain:       "ETH",
    Network:     "mainnet",
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Wallet ID: %s\n", myWallet.WalletID)
fmt.Printf("Status: %s\n", myWallet.Status)
```

### Create an Account

```go
myAccount, err := client.Account.Create(ctx, &account.CreateAccountRequest{
    WalletID:    myWallet.WalletID,
    Chain:       "ethereum",
    Network:     "mainnet",
    Label:       "txacc",
    AccountType: "EOA",
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Account ID: %s\n", myAccount.AccountID)
fmt.Printf("Address: %s\n", myAccount.Address)
```

### Add an Asset (Token)

```go
myAsset, err := client.Asset.Create(ctx, &asset.CreateAssetRequest{
    WalletID:        myWallet.WalletID,
    AccountID:       myAccount.AccountID,
    Chain:           "ETH",
    Network:         "mainnet",
    Symbol:          "USDC",
    Name:            "USD Coin",
    AssetType:       "ERC20",
    ContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    Decimals:        6,
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Asset ID: %s\n", myAsset.AssetID)
fmt.Printf("Balance: %s\n", myAsset.Balance)
```

### List Transactions

```go
transactions, err := client.Transaction.List(ctx, &transaction.ListTransactionsRequest{
    WalletID:  myWallet.WalletID,
    AccountID: myAccount.AccountID,
    Page:      1,
    PageSize:  20,
})
if err != nil {
    log.Fatal(err)
}

for _, tx := range transactions.Items {
    fmt.Printf("TX: %s - %s %s (%s)\n",
        tx.TxHash,
        tx.Amount,
        tx.Chain,
        tx.Status,
    )
}
```

## Configuration

### Environment Configuration

```go
// Sandbox (for testing - default: http://localhost:8080)
client, err := mpcsdk.NewClient(apiKey, apiSecret, configuration.Sandbox())

// Production
client, err := mpcsdk.NewClient(apiKey, apiSecret, configuration.Production())

// Custom environment
client, err := mpcsdk.NewClient(apiKey, apiSecret, configuration.Custom("https://your-api.example.com"))
```

### Environment Variables

```bash
export MPC_API_KEY="ak_test_550e8400e29b41d4a716446655440000"
export MPC_API_SECRET="test_secret_123456"
```

Or create a `.env` file (see `.env.example`):

```bash
cp .env.example .env
# Edit .env with your credentials
```

## API Coverage

### Wallet API

| Operation  | Description                |
| ---------- | -------------------------- |
| **Create** | Create a new MPC wallet    |
| **Get**    | Get wallet details         |
| **List**   | List wallets with filters  |

### Account API

| Operation  | Description                          |
| ---------- | ------------------------------------ |
| **Create** | Create a new account in a wallet     |
| **Get**    | Get account details                  |
| **List**   | List accounts with filters           |

### Asset API

| Operation  | Description                     |
| ---------- | ------------------------------- |
| **Create** | Add a new asset (token)         |
| **Get**    | Get asset details               |
| **List**   | List assets with filters        |

### Transaction API

| Operation | Description                        |
| --------- | ---------------------------------- |
| **Get**   | Get transaction details            |
| **List**  | List transactions with filters     |

## Supported Chains

* Ethereum (ETH)
* Tron (TRX)
* Bitcoin (BTC)
* And more...

## Authentication

The SDK uses JWT authentication with API Key and Secret:

1. SDK automatically requests a JWT token using your API Key/Secret
2. Token is cached and automatically refreshed before expiration
3. All API requests use the JWT token in the Authorization header

## Response Format

All API responses follow a unified format:

```json
{
  "code": 200000,
  "message": "Success",
  "data": { ... },
  "trace_id": "trace-1729612345-abc123",
  "timestamp": 1729612345
}
```

## Error Handling

The SDK returns detailed error information:

```go
wallet, err := client.Wallet.Get(ctx, walletID)
if err != nil {
    // Error includes API error code and trace ID
    log.Printf("Error: %v\n", err)
    return
}
```

Example error format:
```
API error: Wallet not found (code: 404000, trace_id: trace-1729612345-abc123)
```

## Features

### Automatic JWT Token Management

The SDK automatically handles JWT authentication:

* Fetches JWT tokens using API Key/Secret
* Caches tokens until expiration
* Automatically refreshes expired tokens
* Thread-safe token management

### Type Safety

All API requests and responses are strongly typed with proper Go structs:

```go
type Wallet struct {
    WalletID    string `json:"wallet_id"`
    WalletName  string `json:"wallet_name"`
    Description string `json:"description"`
    Chain       string `json:"chain"`
    Network     string `json:"network"`
    WalletType  string `json:"wallet_type"`
    Status      string `json:"status"`
    CreatedAt   string `json:"created_at"`
}
```

## Development

### Project Structure

```
mpc-sdk-go/
├── auth/              # JWT authentication
├── common/            # Shared HTTP client
├── configuration/     # Environment configuration
├── wallet/            # Wallet API
├── account/           # Account API
├── asset/             # Asset API
├── transaction/       # Transaction API
├── test/              # Integration tests
├── mpcsdk.go          # Main SDK client
└── version.go         # SDK version
```

### Build

```bash
# Build all packages
go build ./...

# Run code formatting
gofmt -w .

# Run linter
go vet ./...
```

## Versioning

This SDK follows Semantic Versioning.

Current version: `1.0.0`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Support

* 📧 Email: support@reefiy.com
* 📚 Documentation: https://docs.reefiy.com
* 🐛 Issues: https://github.com/reefiy/mpc-sdk-go/issues

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Changelog

### v1.0.0 (Latest)

* Initial release
* Wallet API support (create, get, list)
* Account API support (create, get, list)
* Asset API support (create, get, list)
* Transaction API support (get, list)
* Automatic JWT token management
* Multi-chain support
* Production ready

---

Made with ❤️ by Reefiy

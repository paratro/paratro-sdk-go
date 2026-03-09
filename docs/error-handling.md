# Error Handling

The Paratro SDK provides structured error types and convenience functions for handling API errors.

## Error Types

### APIError

All API errors are returned as `*paratro.APIError`, which implements the `error` interface:

```go
type APIError struct {
    HTTPStatus int       // HTTP status code (400, 401, 404, etc.)
    ErrorBody            // Embedded error details
}

type ErrorBody struct {
    Code    string `json:"code"`    // Machine-readable error code (e.g., "not_found")
    Type    string `json:"type"`    // Error category (e.g., "not_found_error")
    Message string `json:"message"` // Human-readable description
}
```

### Error Helper Functions

The SDK provides convenience functions for common error checks using `errors.As`:

```go
// IsNotFound reports whether the error is a 404 Not Found response.
paratro.IsNotFound(err) bool

// IsRateLimited reports whether the error is a 429 Too Many Requests response.
paratro.IsRateLimited(err) bool

// IsAuthError reports whether the error is an authentication/authorization error (401 or 403).
paratro.IsAuthError(err) bool
```

## Usage Examples

### Basic Error Handling

```go
wallet, err := client.Wallet.GetWallet(ctx, walletID)
if err != nil {
    if paratro.IsNotFound(err) {
        log.Printf("Wallet %s not found", walletID)
        return
    }
    log.Fatalf("Unexpected error: %v", err)
}
```

### Detailed Error Inspection

```go
import "errors"

asset, err := client.Asset.CreateAsset(ctx, &paratro.CreateAssetRequest{
    AccountID: accountID,
    Symbol:    "USDT",
    Chain:     "ethereum",
})
if err != nil {
    var apiErr *paratro.APIError
    if errors.As(err, &apiErr) {
        switch apiErr.Code {
        case "asset_already_exists":
            log.Println("Asset already added to this account")
        case "account_not_active":
            log.Println("Account is not active")
        case "invalid_parameter":
            log.Printf("Invalid parameter: %s", apiErr.Message)
        default:
            log.Printf("API error [%d]: %s - %s", apiErr.HTTPStatus, apiErr.Code, apiErr.Message)
        }
        return
    }
    // Non-API error (network, JSON decode, etc.)
    log.Fatalf("Request failed: %v", err)
}
```

### Rate Limiting

```go
resp, err := client.Wallet.ListWallets(ctx, &paratro.ListWalletsRequest{Page: 1, PageSize: 100})
if err != nil {
    if paratro.IsRateLimited(err) {
        log.Println("Rate limited, retrying after delay...")
        time.Sleep(5 * time.Second)
        // retry
    }
    return
}
```

### Authentication Errors

```go
wallet, err := client.Wallet.CreateWallet(ctx, &paratro.CreateWalletRequest{
    WalletName: "New Wallet",
})
if err != nil {
    if paratro.IsAuthError(err) {
        log.Println("Authentication failed - check API key and secret")
        return
    }
}
```

## Error Code Reference

See [API Reference - Error Codes](api-reference.md#error-code-reference) for the complete list of error codes.

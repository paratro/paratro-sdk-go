# Webhook Reference

## Overview

The Paratro MPC Message service sends HTTP POST requests to the configured Webhook URL when qualifying transfer transactions are detected, notifying the client of new transaction events. All Webhook requests are authenticated using HMAC-SHA256 signatures (Stripe-style) to ensure authenticity and integrity.

## Trigger Conditions

Webhook notifications are triggered when all of the following conditions are met:

1. **Transaction type match**: The transaction type is one of:
   - `transfer`: Native token transfer (ETH, BNB, TRX, SOL, etc.)
   - `erc20_transfer`: ERC20 token transfer (Ethereum, BSC, Polygon, and other EVM chains)
   - `trc20_transfer`: TRC20 token transfer (Tron chain)
   - `spl_transfer`: SPL token transfer (Solana chain)

2. **Wallet account exists**: The wallet account corresponding to the recipient address (`to`) already exists

3. **Client status**: The wallet client status is `ACTIVE`

4. **Configuration complete**: The client has configured both `WebhookUrl` and `WebhookSecret`

## Request Format

**HTTP Method:** `POST`

**Content-Type:** `application/json`

**Request Headers:**

| Header Name | Description | Example |
|------------|-------------|---------|
| `Content-Type` | Content type | `application/json` |
| `X-Paratro-Timestamp` | Unix timestamp (seconds) | `1704067200` |
| `X-Paratro-Signature` | `v1=` + hex-encoded HMAC-SHA256 signature | `v1=5257a869e7eceb...` |
| `X-Paratro-Api-Key` | Client API Key | `your-api-key` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Event ID (UUID) |
| `chain` | string | Yes | Blockchain name (e.g., `ethereum`, `bsc`, `polygon`, `tron`, `solana`) |
| `txhash` | string | Yes | Transaction hash (unique identifier) |
| `type` | string | Yes | Transaction type: `transfer`, `erc20_transfer`, `trc20_transfer`, or `spl_transfer` |
| `from` | string | Yes | Sender address |
| `to` | string | Yes | Recipient address |
| `symbol` | string | Yes | Token symbol (e.g., `ETH`, `USDT`, `SOL`) |
| `amount` | string | Yes | Amount (in smallest unit, string format) |
| `decimals` | number | Yes | Token decimal places |
| `data` | string | Yes | Hex-encoded transaction input data |
| `risk_score` | number | Yes | Risk advisory score (0-3 low risk, 4-6 medium risk, 7-10 high risk) |

### Native Token Transfer Example

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "chain": "ethereum",
  "txhash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "type": "transfer",
  "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "to": "0x8ba1f109551bD432803012645Hac136c22C92900",
  "symbol": "ETH",
  "amount": "1000000000000000000",
  "decimals": 18,
  "data": "",
  "risk_score": 0
}
```

### ERC20 Token Transfer Example

```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "chain": "ethereum",
  "txhash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "type": "erc20_transfer",
  "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "to": "0x8ba1f109551bD432803012645Hac136c22C92900",
  "symbol": "USDT",
  "amount": "1000000",
  "decimals": 6,
  "data": "0xa9059cbb...",
  "risk_score": 0
}
```

### SPL Token Transfer Example (Solana)

```json
{
  "id": "770e8400-e29b-41d4-a716-446655440002",
  "chain": "solana",
  "txhash": "5xyzSig123abc456def789ghi012jkl345mno678pqr901stu234vwx567yz",
  "type": "spl_transfer",
  "from": "7EYnhQoR9YM3N7UoaKRoA44Uy8JeaZV3qyouov87awMs",
  "to": "8oBNNgSfF9TCh8hN6NfffZUhUo2sGWEm6a5SADVhGtGe",
  "symbol": "USDC",
  "amount": "5000000",
  "decimals": 6,
  "data": "",
  "risk_score": 0
}
```

## Signature Verification

All Webhook requests include an HMAC-SHA256 signature following the Stripe-style signing scheme. The receiver must verify the signature before processing the request.

### Signature Algorithm

**Canonical String:**

```
{unix_timestamp}.{raw_request_body}
```

- `unix_timestamp`: UTC second-level timestamp (from `X-Paratro-Timestamp` header)
- `.`: fixed separator
- `raw_request_body`: raw JSON body (UTF-8 bytes, no preprocessing)

**Signature Computation:**

```
signature = "v1=" + hex(HMAC-SHA256(webhook_secret, canonical_string))
```

- `v1=` prefix: version tag for future algorithm upgrades (e.g., `v2=` for Ed25519)
- hex encoding: lowercase hexadecimal
- HMAC-SHA256: industry standard, used by Stripe / Slack / GitHub

### Verification Steps

```
1. Extract timestamp and signature from headers
2. Validate timestamp format (must be a valid integer)
3. Validate timestamp freshness (|now - timestamp| <= tolerance), anti-replay
4. Read raw request body
5. Build canonical = "{timestamp}.{body}"
6. Compute expected = "v1=" + hex(HMAC-SHA256(secret, canonical))
7. Constant-time comparison of expected vs signature
```

### Go Verification Code

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strconv"
    "time"
)

const (
    signatureVersion = "v1"
    DefaultTolerance = 5 * time.Minute
)

// VerifyPayload verifies a webhook signature.
//   - secret:    shared webhook secret
//   - timestamp: X-Paratro-Timestamp header value
//   - payload:   raw request body bytes
//   - signature: X-Paratro-Signature header value (e.g. "v1=abcdef...")
//   - tolerance: max allowed time drift, 0 to skip time check
func VerifyPayload(secret, timestamp string, payload []byte, signature string, tolerance time.Duration) error {
    // 1. Validate timestamp format
    ts, err := strconv.ParseInt(timestamp, 10, 64)
    if err != nil {
        return fmt.Errorf("webhook: invalid timestamp: %w", err)
    }

    // 2. Anti-replay: validate freshness
    if tolerance > 0 {
        diff := time.Since(time.Unix(ts, 0))
        if diff < 0 {
            diff = -diff
        }
        if diff > tolerance {
            return fmt.Errorf("webhook: timestamp too old (age: %v, tolerance: %v)", diff, tolerance)
        }
    }

    // 3. Compute expected signature
    expected := computeSignature(secret, timestamp, payload)

    // 4. Constant-time comparison (anti timing attack)
    if !hmac.Equal([]byte(expected), []byte(signature)) {
        return fmt.Errorf("webhook: signature mismatch")
    }

    return nil
}

// computeSignature builds the canonical string and computes HMAC-SHA256.
// canonical = "{timestamp}.{payload}", returns "v1=<hex>"
func computeSignature(secret, timestamp string, payload []byte) string {
    canonical := make([]byte, 0, len(timestamp)+1+len(payload))
    canonical = append(canonical, timestamp...)
    canonical = append(canonical, '.')
    canonical = append(canonical, payload...)

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(canonical)

    return signatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}
```

## Signature Verification Notes

1. **Timestamp validation**: It is recommended to validate the timestamp to prevent replay attacks. A typical tolerance window is 5 minutes (default). Use up to 15 minutes for cross-region / high-latency scenarios.

2. **Signature comparison**: Always use a constant-time comparison function (e.g., `hmac.Equal`) to prevent timing attacks.

3. **Raw body**: Use the raw request body bytes for verification. Do not re-serialize or modify the body before computing the signature.

## Response Requirements

**Success Response** - Return HTTP 200:

```json
{
  "success": true,
  "message": "Webhook received successfully"
}
```

**Error Response** - Return appropriate HTTP error status code (4xx or 5xx):

```json
{
  "success": false,
  "error": "Invalid signature",
  "code": "INVALID_SIGNATURE"
}
```

**Response Timeout:** 10 seconds. If the receiver does not respond within 10 seconds, the request is considered failed.

## Error Handling

### Retry Policy

When a Webhook delivery fails (network error or non-2xx response), the server retries with exponential backoff:

- Max attempts: 8
- Backoff sequence: 30s, 1m, 2m, 4m, 8m, 16m, 32m, 2h (capped)

### Client-Side Error Handling Recommendations

1. **Idempotency**: Use the `txhash` field as a unique identifier to ensure duplicate notifications do not cause duplicate processing.

2. **Retry mechanism**: If processing fails, return a 5xx status code. The server will retry according to the retry policy.

3. **Logging**: Log all received Webhook requests, including headers, body, and responses, to facilitate troubleshooting.

4. **Asynchronous processing**: It is recommended to process Webhook requests asynchronously - return a 200 status code immediately, then handle the business logic in the background.

## Security Considerations

1. **HTTPS transport**: It is strongly recommended to configure the Webhook URL with HTTPS to ensure transport security.

2. **Secret protection**: The `WebhookSecret` must be kept secure. Do not expose it or commit it to a code repository.

3. **IP allowlisting**: If possible, configure an IP allowlist to only accept requests from Paratro services.

4. **Signature verification**: You **must** verify the signature of every request and reject any request that fails verification.

5. **Timestamp validation**: Validate the timestamp to prevent replay attacks.

6. **Request body size limit**: It is recommended to set a request body size limit to prevent malicious requests.

## Complete Examples

### Go Example (Using Standard Library)

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strconv"
    "time"
)

const (
    signatureVersion = "v1"
    defaultTolerance = 5 * time.Minute
)

var webhookSecret = os.Getenv("WEBHOOK_SECRET")

type WebhookPayload struct {
    ID       string `json:"id"`
    Chain    string `json:"chain"`
    TxHash   string `json:"txhash"`
    Type     string `json:"type"`
    From     string `json:"from"`
    To       string `json:"to"`
    Symbol   string `json:"symbol"`
    Amount   string `json:"amount"`
    Decimals int    `json:"decimals"`
    Data      string `json:"data"`
    RiskScore int    `json:"risk_score"`
}

type Response struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
    Error   string `json:"error,omitempty"`
    Code    string `json:"code,omitempty"`
}

func main() {
    http.HandleFunc("/webhook/notify", webhookHandler)

    log.Println("Webhook server listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal("Server failed to start:", err)
    }
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondJSON(w, http.StatusMethodNotAllowed, Response{
            Success: false,
            Error:   "Method not allowed",
        })
        return
    }

    // 1. Read raw body
    body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
    if err != nil {
        respondJSON(w, http.StatusInternalServerError, Response{
            Success: false,
            Error:   "Failed to read request body",
        })
        return
    }

    // 2. Verify signature
    timestamp := r.Header.Get("X-Paratro-Timestamp")
    signature := r.Header.Get("X-Paratro-Signature")

    if err := verifyPayload(webhookSecret, timestamp, body, signature, defaultTolerance); err != nil {
        log.Printf("Signature verification failed: %v", err)
        respondJSON(w, http.StatusUnauthorized, Response{
            Success: false,
            Error:   "Invalid signature",
            Code:    "INVALID_SIGNATURE",
        })
        return
    }

    // 3. Parse payload
    var payload WebhookPayload
    if err := json.Unmarshal(body, &payload); err != nil {
        respondJSON(w, http.StatusBadRequest, Response{
            Success: false,
            Error:   "Invalid request body",
        })
        return
    }

    // 4. Use txhash for idempotent deduplication
    // (check if this transaction has already been processed)

    // 5. Async business logic
    go func() {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("Panic processing webhook: %v", r)
            }
        }()
        if err := processWebhookEvent(payload); err != nil {
            log.Printf("Error processing webhook %s: %v", payload.TxHash, err)
        }
    }()

    // 6. Return 200 immediately
    respondJSON(w, http.StatusOK, Response{
        Success: true,
        Message: "Webhook received successfully",
    })
}

// verifyPayload verifies the webhook signature.
func verifyPayload(secret, timestamp string, payload []byte, signature string, tolerance time.Duration) error {
    if timestamp == "" || signature == "" {
        return fmt.Errorf("missing required headers")
    }

    // Validate timestamp format
    ts, err := strconv.ParseInt(timestamp, 10, 64)
    if err != nil {
        return fmt.Errorf("invalid timestamp: %w", err)
    }

    // Anti-replay: validate freshness
    if tolerance > 0 {
        diff := time.Since(time.Unix(ts, 0))
        if diff < 0 {
            diff = -diff
        }
        if diff > tolerance {
            return fmt.Errorf("timestamp too old (age: %v, tolerance: %v)", diff, tolerance)
        }
    }

    // Compute expected signature
    expected := computeSignature(secret, timestamp, payload)

    // Constant-time comparison
    if !hmac.Equal([]byte(expected), []byte(signature)) {
        return fmt.Errorf("signature mismatch")
    }

    return nil
}

// computeSignature builds canonical = "{timestamp}.{payload}" and returns "v1=<hex>".
func computeSignature(secret, timestamp string, payload []byte) string {
    canonical := make([]byte, 0, len(timestamp)+1+len(payload))
    canonical = append(canonical, timestamp...)
    canonical = append(canonical, '.')
    canonical = append(canonical, payload...)

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(canonical)

    return signatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}

func processWebhookEvent(payload WebhookPayload) error {
    log.Printf("Processing: chain=%s, txhash=%s, type=%s, amount=%s %s",
        payload.Chain, payload.TxHash, payload.Type, payload.Amount, payload.Symbol)
    return nil
}

func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(data)
}
```

### Go Example (Using Gin Framework)

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "strconv"
    "time"

    "github.com/gin-gonic/gin"
)

const (
    signatureVersion = "v1"
    defaultTolerance = 5 * time.Minute
    webhookSecret    = "your-webhook-secret" // Use env var in production
)

type WebhookPayload struct {
    ID       string `json:"id"`
    Chain    string `json:"chain"`
    TxHash   string `json:"txhash"`
    Type     string `json:"type"`
    From     string `json:"from"`
    To       string `json:"to"`
    Symbol   string `json:"symbol"`
    Amount   string `json:"amount"`
    Decimals int    `json:"decimals"`
    Data      string `json:"data"`
    RiskScore int    `json:"risk_score"`
}

type Response struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
    Error   string `json:"error,omitempty"`
    Code    string `json:"code,omitempty"`
}

func main() {
    r := gin.Default()
    r.POST("/webhook/notify", webhookHandler)

    if err := r.Run(":8080"); err != nil {
        panic(err)
    }
}

func webhookHandler(c *gin.Context) {
    // 1. Read raw body
    body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
    if err != nil {
        c.JSON(500, Response{Success: false, Error: "Failed to read body"})
        return
    }

    // 2. Verify signature
    timestamp := c.GetHeader("X-Paratro-Timestamp")
    signature := c.GetHeader("X-Paratro-Signature")

    if err := verifyPayload(webhookSecret, timestamp, body, signature, defaultTolerance); err != nil {
        log.Printf("Verification failed: %v", err)
        c.JSON(401, Response{Success: false, Error: "Invalid signature", Code: "INVALID_SIGNATURE"})
        return
    }

    // 3. Parse payload
    var payload WebhookPayload
    if err := json.Unmarshal(body, &payload); err != nil {
        c.JSON(400, Response{Success: false, Error: "Invalid request body"})
        return
    }

    // 4. Async processing
    go func() {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("Panic: %v", r)
            }
        }()
        processWebhookEvent(payload)
    }()

    // 5. Return 200
    c.JSON(200, Response{Success: true, Message: "Webhook received successfully"})
}

func verifyPayload(secret, timestamp string, payload []byte, signature string, tolerance time.Duration) error {
    if timestamp == "" || signature == "" {
        return fmt.Errorf("missing required headers")
    }

    ts, err := strconv.ParseInt(timestamp, 10, 64)
    if err != nil {
        return fmt.Errorf("invalid timestamp: %w", err)
    }

    if tolerance > 0 {
        diff := time.Since(time.Unix(ts, 0))
        if diff < 0 {
            diff = -diff
        }
        if diff > tolerance {
            return fmt.Errorf("timestamp expired (age: %v)", diff)
        }
    }

    expected := computeSignature(secret, timestamp, payload)
    if !hmac.Equal([]byte(expected), []byte(signature)) {
        return fmt.Errorf("signature mismatch")
    }
    return nil
}

func computeSignature(secret, timestamp string, payload []byte) string {
    canonical := make([]byte, 0, len(timestamp)+1+len(payload))
    canonical = append(canonical, timestamp...)
    canonical = append(canonical, '.')
    canonical = append(canonical, payload...)

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(canonical)
    return signatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}

func processWebhookEvent(payload WebhookPayload) {
    log.Printf("Processing: chain=%s, txhash=%s, type=%s", payload.Chain, payload.TxHash, payload.Type)
}
```

## Security Guarantees

| Threat | Mitigation |
|--------|-----------|
| Body tampering | HMAC-SHA256 guarantees integrity |
| Signature forgery | Requires webhook_secret, cannot forge |
| Replay attack | Timestamp window validation (default 5 min) |
| Timing attack | `hmac.Equal` constant-time comparison |
| Future algorithm upgrade | `v1=` prefix, add `v2=` without breaking |

## FAQ

**Q: How do I test Webhooks?**
A: You can use tools like [ngrok](https://ngrok.com/) or [localtunnel](https://localtunnel.github.io/www/) to expose your local service to the internet, then configure the Webhook URL accordingly.

**Q: What if Webhook processing takes too long?**
A: It is recommended to use an asynchronous processing pattern: return a 200 status code immediately, then handle the business logic in the background.

**Q: How do I prevent duplicate processing?**
A: Use the transaction hash (`txhash` field) as a unique identifier and check whether the transaction has already been processed before handling it.

**Q: What should I do if signature verification fails?**
A: Check the following:
1. Whether the `WebhookSecret` is correct
2. Whether the raw request body is being used (not re-serialized or modified by middleware)
3. Whether the timestamp is within the valid range (default 5 minutes)
4. Whether the signature has the `v1=` prefix

**Q: What transaction types are supported?**
A: The following transaction types are currently supported:
- `transfer`: Native token transfer (ETH, BNB, TRX, SOL, BTC, etc.)
- `erc20_transfer`: ERC20 token transfer (Ethereum, BSC, Polygon)
- `trc20_transfer`: TRC20 token transfer (Tron)
- `spl_transfer`: SPL token transfer (Solana)

**Q: What tolerance window should I use?**

| Scenario | Window |
|----------|--------|
| Default | 5 minutes |
| High security | 2 minutes |
| Cross-region / high latency | 15 minutes |
| Testing / debugging | 0 (skip check) |

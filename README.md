# Paratro MPC Wallet Gateway Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/paratro/paratro-sdk-go.svg)](https://pkg.go.dev/github.com/paratro/paratro-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/paratro/paratro-sdk-go)](https://goreportcard.com/report/github.com/paratro/paratro-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Go SDK for the Paratro MPC Wallet Gateway.

> **Upgrading from 1.7 or earlier?** 1.8.1 is not a purely additive release:
> it moves to the unified transaction entry `POST /api/v1/transactions`
> (`POST /api/v1/transfer` is retired, HTTP 410) and removes `X402Sign`
> (endpoint retired, HTTP 410). The module path is unchanged
> (`github.com/paratro/paratro-sdk-go`). See the **⚠️ Breaking** section of
> [CHANGELOG.md](CHANGELOG.md) for the migration guide.

## Features

- MPC Wallets - Create and manage MPC wallets
- Accounts and Assets - Multi-chain accounts, native and token assets
- Transactions - One entry for three operations:
  - `TRANSFER` - send funds to an address (asynchronous signing)
  - `PROGRAM_CALL` - co-sign a counterparty-built Solana transaction (xChange swap)
  - `CONTRACT_CALL` - sign an xChange `executeSwap` on an EVM chain (EIP-2612 permit + call)
- Transaction Tracking - Get / list transactions
- x402 Facilitator - verify, settle, settle status, settlement list
- Typed errors - `*APIError` with the gateway's `{code,type,message}`, machine-readable rejection reason tags, classifiers for 400/403/404/410/503
- Configurable HTTP timeout sized for the synchronous `PROGRAM_CALL` / `CONTRACT_CALL` (default 200s, above the gateway's 180s write timeout)
- JWT authentication with automatic token refresh (and one automatic retry on `401 token_expired`)
- Webhook signature verification and event parsing

## Installation

```bash
go get github.com/paratro/paratro-sdk-go@latest
```

**Requirements**: Go 1.21 or higher

```go
import paratro "github.com/paratro/paratro-sdk-go"
```

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
    client, err := paratro.NewMPCClient("your-api-key", "your-api-secret", paratro.Sandbox())
    if err != nil {
        log.Fatal(err)
    }
    ctx := context.Background()

    // 1. Create wallet (asynchronous: wait for status and key_status == ACTIVE)
    wallet, err := client.Wallet.CreateWallet(ctx, &paratro.CreateWalletRequest{
        WalletName:  "My Wallet",
        Description: "Primary wallet",
    })
    if err != nil {
        log.Fatal(err)
    }

    // 2. Create account (network is derived from chain)
    account, err := client.Account.CreateAccount(ctx, &paratro.CreateAccountRequest{
        WalletID: wallet.WalletID,
        Chain:    "ethereum",
        Label:    "Deposit Account",
    })
    if err != nil {
        log.Fatal(err)
    }

    // 3. Add asset
    _, err = client.Asset.CreateAsset(ctx, &paratro.CreateAssetRequest{
        AccountID: account.AccountID,
        Symbol:    "USDC",
        Chain:     "ethereum",
    })
    if err != nil {
        log.Fatal(err)
    }

    // 4. TRANSFER via the unified entry
    resp, err := client.Transaction.CreateTransaction(ctx, &paratro.TransferRequest{
        FromAddress: account.Address,
        ToAddress:   "0xbbbb...",
        Chain:       "ethereum",
        TokenSymbol: "USDC",
        Amount:      "10.5",          // human-readable decimal
        ReferenceID: "order-2026-0001", // your business reference (idempotency)
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("tx_id=%s status=%s\n", resp.TxID, resp.Status) // status PENDING, signed asynchronously

    // 5. Follow up
    tx, err := client.Transaction.GetTransaction(ctx, resp.TxID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%s %s %s\n", tx.Status, tx.TxHash, tx.Amount)
}
```

## Transactions: the unified entry

`client.Transaction.CreateTransaction(ctx, req)` sends `POST /api/v1/transactions`.
`req` is one of three request types; the SDK sets the `operation` field.

| Request type | `operation` | Answer |
|---|---|---|
| `paratro.TransferRequest` | `TRANSFER` | `200 {tx_id, status:"PENDING"}` - signed asynchronously |
| `paratro.ProgramCallRequest` | `PROGRAM_CALL` | `200 {tx_id, status:"BROADCAST", tx_hash}` or `202 {tx_id, status:"PENDING"}` |
| `paratro.ContractCallRequest` | `CONTRACT_CALL` | `200 {tx_id, status:"BROADCAST", tx_hash}` or `202 {tx_id, status:"PENDING"}` |

Common fields: `FromAddress`, `Chain`, `Memo` (≤ 100 chars), `ReferenceID`
(≤ 100 chars; reuse within the same client → `400 Duplicate reference_id`).

`client.Transaction.CreateTransfer(ctx, &paratro.TransferRequest{...})` is kept from
1.7 and is exactly `CreateTransaction` with a `TransferRequest`.

### PROGRAM_CALL (Solana)

The counterparty builds and partially signs the swap transaction; the gateway
verifies it against your `OPERATION_RULES` policy, co-signs the fee-payer slot
and broadcasts.

```go
resp, err := client.Transaction.CreateTransaction(ctx, &paratro.ProgramCallRequest{
    FromAddress:       payerWallet,        // fee payer (AccountKeys[0]) with an empty signature slot
    Chain:             "solana",
    SignedTransaction: counterpartySigned, // base64 or 0x-hex
    ReceiveAddress:    receiveWallet,      // optional, defaults to FromAddress
    ReferenceID:       "quote-" + quoteID,
})
```

Shape requirements (any violation → `400 Rejected: …`): exactly three
instructions (Memo + your `TransferChecked` out + counterparty `TransferChecked`
in), only System / Token / Token-2022 / ATA / Memo programs and all of them in
the policy's `allowed_programs`, no Address Lookup Tables, your wallet in the
fee-payer slot with an empty signature, destination ATA owned by a policy
counterparty, both mints in `allowed_mints`, amount within the outgoing mint's
policy limit (`asset_rules.limits.solana[mint]` in token units, or the legacy
smallest-unit `single_limit` / `daily_limit` when the mint has no entry).

### CONTRACT_CALL (EVM, xChange `executeSwap`)

```go
resp, err := client.Transaction.CreateTransaction(ctx, &paratro.ContractCallRequest{
    FromAddress:    payerWallet,   // incoming.from, permit owner, tx sender — the quote must be for it
    Chain:          "ethereum",
    ReceiveAddress: payerWallet,   // outgoing.to, optional (defaults to FromAddress)
    ReferenceID:    "quote-" + quoteID,
    ContractCall: paratro.ContractCall{
        QuoteID:    "0x<bytes32>",
        Expiration: 1789449058, // unix seconds, ≤ now + max_execution_timeout_seconds
        Incoming: paratro.ContractCallIncomingLeg{ // you → counterparty
            To: "0xcf8a…", Token: "0x59fb…(bUSDC)", Amount: "10000000",
        },
        Outgoing: paratro.ContractCallOutgoingLeg{ // counterparty → you
            From: "0xcf8a…", To: payerWallet, Token: "0xa55a…(AAPLx)", Amount: "42000000000000000",
        },
        CounterpartySignature: "0x<65 bytes>", // counterparty's EIP-712 signature; verified by the contract
        // PermitDeadline: 0 → now + min(max_permit_lifetime_seconds, 300)
    },
})
```

Amounts are **smallest-unit integer strings** (unlike `TRANSFER`, whose amount
is in token units). The contract address is **not part of the request** - the
gateway takes it from the policy's `call_rules.allowed_contracts[chain]` - and
the native value is always 0. Policy limits are authored per token in token
units (`asset_rules.limits[chain][token]`, e.g. `"0.5"`); the gateway converts
them with the token's registered decimals, checks registration before limits,
and limit rejections quote both sides in token units
(`limit_per_transaction: 1 CORZx exceeds per-transaction limit 0.5 CORZx`).

### Handling 202 (outcome unknown)

For `PROGRAM_CALL` / `CONTRACT_CALL` the gateway may answer `202` with
`status:"PENDING"`: the transaction row exists but the signing engine did not
answer in time. It may still be signing or may already be broadcast.

```go
resp, err := client.Transaction.CreateTransaction(ctx, req)
if err != nil { /* see Error handling */ }
if resp.Accepted() {
    // Poll GET /api/v1/transactions/{tx_id} until the status settles.
    // Do NOT resubmit: the same reference_id is a duplicate, a new one may pay twice.
    for attempt := 0; attempt < 40; attempt++ { // ~2 minutes; hand over to webhooks after that
        time.Sleep(3 * time.Second)
        tx, err := client.Transaction.GetTransaction(ctx, resp.TxID)
        if err != nil {
            log.Println("poll:", err) // transient 5xx / token refresh: keep polling
            continue
        }
        if tx.Status != paratro.StatusPending {
            break
        }
    }
}
```

`Accepted()` is true for HTTP 202 and also for a `PROGRAM_CALL` /
`CONTRACT_CALL` answered `200 status=PENDING` — that is what an
`Idempotency-Key` replay of a 202 looks like (the gateway replays the cached
body as 200). `resp.HTTPStatus` and `resp.Operation` carry the raw values.

### Timeouts

`PROGRAM_CALL` / `CONTRACT_CALL` are synchronous: the gateway holds the
connection while the signing engine signs and broadcasts. The gateway's own
ceilings are an engine budget of 120s, a wait of 150s (budget + 30s broadcast
margin) for the engine before it answers `202`, and a server write timeout of
180s after which it closes the connection. The SDK's HTTP timeout is
`Config.Timeout`, defaulting to `paratro.DefaultTimeout` (200s) — above the
write timeout — so that the gateway gives up first and you still get a `202`
with a `tx_id`. Do not lower it, and do not pass a context deadline shorter
than that, for these two operations.

If the call still fails at the transport level (timeout, connection reset) you
have no `tx_id` and the outcome is as unknown as a 202. Do **not** resubmit
with a new `reference_id`. Provided you set a `reference_id`, replaying the
identical request (same `reference_id`, same `Idempotency-Key`) is safe: with
an `Idempotency-Key` you get the original body if the first attempt completed
with 2xx (cached 24h under that key); otherwise `400 Duplicate reference_id` if
its row exists; or a normal answer if it never created a row — the
`reference_id` unique key allows at most one transaction per reference.
`GET /transactions` cannot filter by `reference_id`, so keep your own
`reference_id → tx_id` record.

### Optional `Idempotency-Key`

`POST /api/v1/transactions` and `POST /api/v1/x402/settle` also honour an
`Idempotency-Key` header: a repeated POST with the same key from the same client
within 24 hours returns the cached body of the first 2xx response (always as
HTTP 200, even if the original was 202). Pass it with
`paratro.WithIdempotencyKey("…")`. It is independent of `reference_id`.

## Error Handling

Every non-2xx answer is a `*paratro.APIError` with `HTTPStatus` and the
gateway's `Code` / `Type` / `Message`.

```go
resp, err := client.Transaction.CreateTransaction(ctx, req)
switch {
case err == nil:
    // ok
case paratro.IsRejected(err):
    // 400 "Rejected: <tag>: <detail>" — policy / verifier rejection; retry with a NEW reference_id
    switch paratro.RejectionReason(err) {
    case paratro.ReasonExpirationPassed:
        // quote expired, fetch a new one
    case paratro.ReasonLimitDaily, paratro.ReasonLimitPerTransaction:
        // policy limits
    default:
        log.Println("rejected:", paratro.RejectionReason(err), err)
    }
case paratro.IsDuplicateReferenceID(err): // 400: this reference_id already has a row (maybe a FAILED one) — never resubmit it
case paratro.IsInsufficientBalance(err):  // 400 insufficient_balance
case paratro.IsTransactionFailed(err):    // 400 transaction_failed: row created, engine failed it; retry = new reference_id
    log.Println(paratro.RejectionReason(err)) // engine tag when there is one
case paratro.IsAddressBlacklisted(err):   // 403 address_blacklisted: TRANSFER destination blacklisted
case paratro.IsForbidden(err):            // 403 forbidden: no OPERATION_RULES policy allows it
case paratro.IsNotFound(err):             // 404: address/asset not yours, token not credited
case paratro.IsServiceUnavailable(err):   // 503: engine busy / chain RPC down — retry later with a NEW reference_id
case paratro.IsEndpointRetired(err):      // 410
default:
    var apiErr *paratro.APIError
    if errors.As(err, &apiErr) {
        log.Printf("%d %s %s", apiErr.HTTPStatus, apiErr.Code, apiErr.Message)
    }
}
```

Reason tags are exported as `paratro.Reason*` constants (e.g.
`ReasonCounterpartyNotRegistered`, `ReasonLimitDaily`, `ReasonPermitDeadlinePassed`,
`ReasonFeePayer`), including the engine's own `400 transaction_failed` verdicts
(`ReasonRequestDigestMismatch`, `ReasonReceiverNotOurs`, `ReasonPermitOwnerMismatch`,
…). See [docs/error-handling.md](docs/error-handling.md) for the full list and
which operation produces which. The set is not closed: treat an unknown tag as a
rejection you have not seen yet.

**Retrying.** A 4xx/5xx means the request did not reach the chain, not that
nothing was stored: the gateway raises "engine busy" (503), the engine's own
verdict (400 `transaction_failed`) and the CONTRACT_CALL post-sign check (400
`Rejected`) after the transaction row was inserted, and that row keeps the
`reference_id` (its unique key ignores status). So a retry always uses a
**new** `reference_id`; the old one answers `400 Duplicate reference_id`. Only
a `202` and a transport failure are never resubmitted (see
[Timeouts](#timeouts)). Full table: [docs/error-handling.md → Retrying](docs/error-handling.md#retrying).

## x402 Facilitator

```go
verify, err := client.X402.X402Verify(ctx, map[string]interface{}{
    "x402Version":    2,
    "paymentPayload": paymentPayload, // {"payload": …, "accepted": paymentRequirements}
})
settle, err := client.X402.X402Settle(ctx, settlePayload, paratro.WithIdempotencyKey(key))
status, err := client.X402.X402SettleStatus(ctx, settle.TxID)
list, err := client.X402.X402ListSettlements(ctx, &paratro.ListX402SettlementsRequest{Status: "SETTLED", Page: 1, PageSize: 20})
```

`POST /api/v1/x402/sign` was retired by the gateway (HTTP 410); there is no
`X402Sign` in 2.x and the unified entry does not accept `operation=X402`.

## Webhooks

```go
func webhookHandler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    err := paratro.VerifyWebhookSignature(
        "whsec_your_webhook_secret",
        r.Header.Get("X-Paratro-Timestamp"),
        body,
        r.Header.Get("X-Paratro-Signature"),
        paratro.DefaultWebhookTolerance,
    )
    if err != nil {
        http.Error(w, "Invalid signature", http.StatusUnauthorized)
        return
    }
    event, err := paratro.ParseWebhookEvent(body)
    if err != nil {
        http.Error(w, "Invalid payload", http.StatusBadRequest)
        return
    }
    switch event.EventType {
    case paratro.EventTransactionConfirming: // inbound deposit seen, confirmations accumulating
    case paratro.EventTransactionConfirmed:  // deposit or outbound tx (TRANSFER / PROGRAM_CALL / CONTRACT_CALL) confirmed
    case paratro.EventTransactionFailed:     // outbound tx failed on chain
    case paratro.EventTransferCredited:      // payment from another Paratro-hosted wallet credited
    case paratro.EventX402SettlementConfirmed:
    }
    w.WriteHeader(http.StatusOK)
}
```

## Configuration

```go
client, err := paratro.NewMPCClient(apiKey, apiSecret, paratro.Sandbox())     // https://api-sandbox.paratro.com
client, err := paratro.NewMPCClient(apiKey, apiSecret, paratro.Production())  // https://api.paratro.com
client, err := paratro.NewMPCClient(apiKey, apiSecret, paratro.Custom("https://your-api.example.com"))
client, err := paratro.NewMPCClient(apiKey, apiSecret, &paratro.Config{
    BaseURL: "https://api-sandbox.paratro.com",
    Timeout: 4 * time.Minute, // HTTP timeout for every call; 0 = paratro.DefaultTimeout (200s)
})
```

`Config.Timeout` is the `http.Client` timeout for every SDK call, including
`POST /auth/token`; the context deadline you pass per call applies on top and
also covers the token refresh the SDK may make for that call. The default,
`paratro.DefaultTimeout` (200s), is deliberately above the gateway's 180s
write timeout for the synchronous `PROGRAM_CALL` / `CONTRACT_CALL` (engine
budget 120s, 150s wait for the engine before a `202`) — see
[Timeouts](#timeouts) before lowering it.

Authentication: the SDK calls `POST /api/v1/auth/token` with `X-API-Key` /
`X-API-Secret`, caches the JWT until `expires_in` minus a 2-minute buffer, and
on a `401 token_expired` fetches a new token and retries the call once. The
caller's IP must be in the client's IP allowlist. Redirects are never followed.

## Documentation

- [API Reference](docs/api-reference.md) - endpoints, request/response shapes
- [Error Handling](docs/error-handling.md) - error codes, reason tags, classifiers
- [Webhook Reference](docs/webhook-reference.md) - signature verification and events
- [CHANGELOG](CHANGELOG.md) - 1.7 → 1.8.1 migration (⚠️ Breaking section)

## Development

```
paratro-sdk-go/
├── client.go                # HTTP client, token retry, request options
├── errors.go                # APIError, error codes, reason tags, classifiers
├── config.go                # Environment configuration
├── token.go                 # JWT token management
├── wallet.go / account.go / asset.go
├── transaction.go           # Unified entry: TransferRequest / ProgramCallRequest / ContractCallRequest, Get / List
├── transfer.go              # pre-1.8 CreateTransfer compatibility wrapper
├── x402.go                  # x402 facilitator (verify / settle / status / settlements)
├── webhook.go               # Webhook verification & event parsing
├── client_contract_test.go  # Wire-format tests against a fake gateway (no network)
├── client_timeout_test.go   # Timeout / context-deadline tests (one 35s slow-gateway case, skipped with -short)
├── docs_guard_test.go       # Fails if any doc/comment promises a same-reference_id retry
├── integration_test.go      # Integration tests (need credentials)
└── examples/                # complete, transfer, operations
```

```bash
go build ./...
go vet ./...
SKIP_INTEGRATION_TESTS=true go test -short -count=1 ./...   # contract tests only, no network, ~1s
SKIP_INTEGRATION_TESTS=true go test -count=1 ./...          # plus the 35s slow-gateway timeout test
MPC_API_KEY=… MPC_API_SECRET=… go test -count=1 ./...        # plus sandbox integration tests
```

## Support

- Email: hello@paratro.com
- Documentation: https://docs.paratro.com
- Issues: https://github.com/paratro/paratro-sdk-go/issues

## License

MIT - see [LICENSE.md](LICENSE.md).

# API Reference (Go SDK 2.x)

Base URLs: `paratro.Sandbox()` → `https://api-sandbox.paratro.com`,
`paratro.Production()` → `https://api.paratro.com`. All paths below are under
`/api/v1`. Every call except `POST /auth/token` needs `Authorization: Bearer <jwt>`;
the SDK handles that.

Successful responses are the bare object (no envelope). Lists are
`{"data":[…],"total":N,"has_more":bool}`. Errors are
`{"code","type","message"}` → `*paratro.APIError` (see [error-handling.md](error-handling.md)).

## Authentication

`POST /auth/token` with headers `X-API-Key` / `X-API-Secret` →
`{"token","expires_in","token_type":"Bearer","client":{…}}`.

- The SDK caches the JWT until `expires_in - 120s` and refreshes on demand.
- `401 token_expired` on any call → the SDK refreshes and retries that call once.
- The caller's IP must be in the client's IP allowlist (`403 IP not allowed`).

## Transactions

### `Transaction.CreateTransaction(ctx, req, opts...)` - `POST /transactions`

`req` is a `TransferRequest`, `ProgramCallRequest` or `ContractCallRequest`.
The SDK writes the `operation` field. Optional `paratro.WithIdempotencyKey(k)`
sets the `Idempotency-Key` header (24h replay of the first 2xx body, replayed as
HTTP 200).

Common request fields:

| JSON | Go | Notes |
|---|---|---|
| `operation` | (set by the request type) | `TRANSFER` \| `PROGRAM_CALL` \| `CONTRACT_CALL`; anything else → `400 Unsupported operation` |
| `reference_id` | `ReferenceID` | optional, ≤ 100; per-client unique → `400 Duplicate reference_id` |
| `from_address` | `FromAddress` | required, your account |
| `chain` | `Chain` | required |
| `memo` | `Memo` | optional, ≤ 100 |

#### `TransferRequest` (`operation=TRANSFER`)

| JSON | Go | Notes |
|---|---|---|
| `to_address` | `ToAddress` | required, ≠ from_address |
| `token_symbol` | `TokenSymbol` | required |
| `amount` | `Amount` | required, positive decimal string, ≤ 18 decimals |

Answer: `200 {"tx_id","status":"PENDING","message":"Transfer task created"}`.
Signing is asynchronous; follow with `GetTransaction` or webhooks.

#### `ProgramCallRequest` (`operation=PROGRAM_CALL`, chain `solana`)

| JSON | Go | Notes |
|---|---|---|
| `signed_transaction` | `SignedTransaction` | required; counterparty-signed tx, base64 or 0x-hex, ≤ 4096 chars |
| `receive_address` | `ReceiveAddress` | optional, your receiving account; default = from_address |

Shape rules (violations → `400 Rejected: <tag>`): exactly 3 instructions
(Memo + your `TransferChecked` + counterparty `TransferChecked`); only
System / Token / Token-2022 / ATA / Memo programs, all in policy
`call_rules.allowed_programs`; no Address Lookup Tables; your wallet in the
fee-payer slot (`AccountKeys[0]`) with an empty signature slot; outgoing
destination ATA owned by a policy counterparty; incoming destination = ATA of
`receive_address`; both mints in `asset_rules.allowed_mints` and registered;
amount ≤ the outgoing mint's per-transaction limit, daily total ≤ its daily
limit (`asset_rules.limits.solana[mint]` in token units, or the legacy
smallest-unit `single_limit` / `daily_limit` when the mint has no entry).
`tx_hash` = `signatures[0]`.

#### `ContractCallRequest` (`operation=CONTRACT_CALL`, EVM chains)

| JSON | Go | Notes |
|---|---|---|
| `receive_address` | `ReceiveAddress` | optional, = `outgoing.to`; default = from_address |
| `contract_call.quote_id` | `ContractCall.QuoteID` | bytes32 hex, 0x optional |
| `contract_call.expiration` | `ContractCall.Expiration` | unix seconds; future, ≤ now + `fee_limits.max_execution_timeout_seconds` |
| `contract_call.incoming.{to,token,amount}` | `ContractCall.Incoming` | you → counterparty; `to` ∈ `counterparties`, `token` ∈ `payment_tokens`, amount (smallest unit) ≤ the token's per-transaction limit and daily ≤ its daily limit (`asset_rules.limits[chain][token]` in token units, or the legacy `single_limit` / `daily_limit`) |
| `contract_call.outgoing.{from,to,token,amount}` | `ContractCall.Outgoing` | counterparty → you; `from` ∈ `counterparties`, `to` = your wallet, `token` ∈ `target_tokens` |
| `contract_call.counterparty_signature` | `ContractCall.CounterpartySignature` | EIP-712 signature (hex); verified by the contract, not the gateway |
| `contract_call.permit_deadline` | `ContractCall.PermitDeadline` | optional; 0 → now + min(`max_permit_lifetime_seconds`, 300) |

Amounts are smallest-unit decimal integer strings (only `TRANSFER` amounts are
in token units). The contract address comes
from the policy (`call_rules.allowed_contracts[chain]`), never from the request.
Native value is always 0. `from_address` is `incoming.from`, the permit owner
and the sender - the quote must be generated for it.

#### Response - `CreateTransactionResponse`

| JSON | Go | |
|---|---|---|
| `tx_id` | `TxID` | |
| `status` | `Status` | `PENDING` or `BROADCAST` |
| `message` | `Message` | |
| `tx_hash` | `TxHash` | only when `BROADCAST` |
| - | `HTTPStatus` | 200 or 202 |
| - | `Operation` | the request's operation (SDK-filled; the gateway does not echo it) |
| - | `Accepted()` | `HTTPStatus == 202`, or `PROGRAM_CALL` / `CONTRACT_CALL` with `status == PENDING` (an `Idempotency-Key` replay of a 202 is served as 200) |

| HTTP | Meaning |
|---|---|
| `200 status=PENDING` | TRANSFER queued |
| `200 status=BROADCAST` + `tx_hash` | PROGRAM_CALL / CONTRACT_CALL broadcast; confirmation via `GetTransaction` / webhooks |
| `202 status=PENDING` | engine outcome unknown - poll `GetTransaction(tx_id)`; do not resubmit |
| `400 Rejected: <tag>: …` | policy / verifier rejection (`IsRejected`, `RejectionReason`); not on chain, but the CONTRACT_CALL post-sign check rejects after the row was created — retry with a new `reference_id` |
| `400 Duplicate reference_id` | `IsDuplicateReferenceID` |
| `400 insufficient_balance` | `IsInsufficientBalance` |
| `400 transaction_failed` | row created, engine failed it; message `"<OP> failed: <tag>"` (`IsTransactionFailed`, `RejectionReason`) |
| `403 forbidden` | no `OPERATION_RULES` policy allows the operation/chain (`IsForbidden`) |
| `403 address_blacklisted` | TRANSFER to a blacklisted `to_address` (`IsAddressBlacklisted`; `IsForbidden` is also true) |
| `404` | address / asset not this client's, or token not credited yet (`IsNotFound`) |
| `503` | engine busy, chain RPC unavailable, or operation not enabled on this gateway (`IsServiceUnavailable`). "Engine busy" is raised after the row was created and the row keeps the `reference_id`: retry with a **new** `reference_id`, the same one answers `400 Duplicate reference_id` |

Retry rules in full: [error-handling.md → Retrying](error-handling.md#retrying).
Short form: a retry always uses a new `reference_id`; a `202` (or its
`Idempotency-Key` replay, which arrives as `200 status=PENDING`) and a transport
failure are never resubmitted.

`PROGRAM_CALL` / `CONTRACT_CALL` are synchronous: the gateway holds the
connection while it waits for the signing engine (engine budget 120s; it waits
150s — budget + 30s broadcast margin — before answering `202`; server write
timeout 180s, after which it closes the connection). The SDK's HTTP timeout
defaults to `paratro.DefaultTimeout` (200s, above the write timeout) — see
[Configuration](#configuration) — and the context you pass must not be shorter
for these two operations. A client-side timeout has no `tx_id`;
`GET /transactions` cannot filter by `reference_id`.

### `Transaction.CreateTransfer(ctx, *TransferRequest, opts...)`

1.7 compatibility wrapper = `CreateTransaction` with a `TransferRequest`.
`CreateTransferRequest` and `TransferResponse` are aliases.

### `Transaction.GetTransaction(ctx, txID)` - `GET /transactions/{id}`

`Transaction{tx_id, wallet_id, client_id, chain, transaction_type, from_address,
to_address, token_symbol, amount, status, tx_hash, risk_score?, risk_level?, created_at}`.

### `Transaction.ListTransactions(ctx, *ListTransactionsRequest)` - `GET /transactions`

Query: `wallet_id`, `account_id`, `chain`, `page` (default 1), `page_size`
(default 20, max 100). Returns `ListTransactionsResponse{Items, Total, HasMore}`.

## Wallets / Accounts / Assets

| Method | Endpoint |
|---|---|
| `Wallet.CreateWallet` | `POST /wallets` |
| `Wallet.GetWallet` | `GET /wallets/{id}` |
| `Wallet.ListWallets` | `GET /wallets` |
| `Account.CreateAccount` | `POST /accounts` |
| `Account.GetAccount` | `GET /accounts/{id}` |
| `Account.ListAccounts` | `GET /accounts?wallet_id=` |
| `Asset.CreateAsset` | `POST /assets` |
| `Asset.GetAsset` | `GET /assets/{id}` |
| `Asset.ListAssets` | `GET /assets?account_id=` |

Wallets are created asynchronously: wait for `status` and `key_status` ==
`ACTIVE` before creating accounts. Account `network` is derived from `chain`.

## x402 facilitator

| Method | Endpoint | Response |
|---|---|---|
| `X402.X402Verify(ctx, payload)` | `POST /x402/verify` | `X402VerifyResponse{isValid, invalidReason?, payer?}` |
| `X402.X402Settle(ctx, payload, opts...)` | `POST /x402/settle` (honours `Idempotency-Key`) | `X402SettleResponse{success, txId?, transaction, errorReason?, payer?, network?}` |
| `X402.X402SettleStatus(ctx, txID)` | `GET /x402/settle/{tx_id}` | `X402SettleStatusResponse{success, txId, status, txHash?, network}` |
| `X402.X402ListSettlements(ctx, *ListX402SettlementsRequest)` | `GET /x402/settlements?status=&page=&page_size=` | list of `X402Settlement{tx_id, chain, from_address, to_address, amount, status, valid_before, signature_v/r/s?, created_at}` |

`payload` for verify / settle is the Coinbase-compatible facilitator request
`{"x402Version":1|2,"paymentPayload":…,"paymentRequirements":…(v1 only)}`,
passed as `map[string]interface{}`.

## Configuration

```go
paratro.Sandbox()                                   // https://api-sandbox.paratro.com, Timeout: DefaultTimeout
paratro.Production()                                // https://api.paratro.com
paratro.Custom("https://gw.example")
&paratro.Config{BaseURL: "…", Timeout: 4 * time.Minute}
```

| Field | Default | Notes |
|---|---|---|
| `BaseURL` | - | required |
| `Timeout` | `paratro.DefaultTimeout` = 200s | `http.Client.Timeout` for every SDK call incl. `POST /auth/token`; the per-call context deadline applies on top. Keep it ≥ 200s for clients that send `PROGRAM_CALL` / `CONTRACT_CALL`: the gateway waits up to 150s for the engine before answering `202` and closes the connection at its 180s write timeout, so the SDK must outlast both |

## Retired endpoints (HTTP 410)

| Endpoint | Replacement |
|---|---|
| `POST /transfer` | `POST /transactions` with `operation=TRANSFER` (`CreateTransfer` already does this) |
| `POST /x402/sign` | none - `operation=X402` is not accepted by the unified entry |

Body: `{"code":"invalid_parameter","type":"endpoint_retired","message":"This endpoint has been retired. Use …"}` → `IsEndpointRetired`.

## OPERATION_RULES policy (portal)

`PROGRAM_CALL` / `CONTRACT_CALL` are only allowed when the client has an
`OPERATION_RULES` policy (action `AUTO_APPROVE`) covering the operation and
chain. Rule JSON - request amounts are smallest-unit integers; `asset_rules.limits`
is per token in **token units**, the legacy `single_limit` / `daily_limit` are
smallest-unit integers used only for tokens without a `limits` entry:

```json
{
  "operations": ["PROGRAM_CALL", "CONTRACT_CALL"],
  "chains": ["ethereum", "solana"],
  "networks": ["testnet"],
  "call_rules": {
    "allowed_programs": ["11111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"],
    "allowed_contracts": { "ethereum": "0x4b4fc9f98e99c2e3c58d0551191da16feb3d7a7a" }
  },
  "recipient_rules": { "counterparties": { "ethereum": ["0x…"], "solana": ["…"] } },
  "asset_rules": {
    "allowed_mints":  { "solana":   ["…"] },
    "payment_tokens": { "ethereum": ["0x…"] },
    "target_tokens":  { "ethereum": ["0x…"] },
    "limits": {
      "ethereum": { "0x…": { "single": "50", "daily": "200" } },
      "solana":   { "…":  { "single": "50", "daily": "200" } }
    },
    "single_limit": "50000000",
    "daily_limit":  "200000000"
  },
  "fee_limits": { "max_execution_timeout_seconds": 900, "max_permit_lifetime_seconds": 600 }
}
```

Missing limits fail closed (`Rejected: limit_not_configured`); a `limits` entry
that does not convert to a whole number of smallest units at the token's
registered decimals is `Rejected: limit_invalid`. Registration (counterparty,
tokens, mints) is checked before the limits. Policy updates require
`expected_revision` (409 on conflict).

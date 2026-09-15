# Changelog

## 1.8.1 - 2026-09-15

Aligns the SDK with the gateway's unified transaction entry. The module path
stays `github.com/paratro/paratro-sdk-go` (no major-version bump), but **1.8.1
is not a purely additive release** — read the ⚠️ Breaking section before
upgrading.

### ⚠️ Breaking

- **`X402Sign` removed.** `POST /api/v1/x402/sign` was retired by the gateway and
  answers `410 {"code":"invalid_parameter","type":"endpoint_retired"}`. The
  unified entry does **not** accept `operation=X402` (it answers
  `400 Unsupported operation`), so there is no replacement call in this SDK.
  `X402SignRequest` / `X402SignResponse` are gone. The facilitator side
  (`X402Verify`, `X402Settle`, `X402SettleStatus`, `X402ListSettlements`) stays.
- **`CreateTransfer` now calls `POST /api/v1/transactions` with
  `operation=TRANSFER`.** `POST /api/v1/transfer` is retired (410). The method,
  `CreateTransferRequest` and `TransferResponse` names are kept as aliases of
  `TransferRequest` / `CreateTransactionResponse`; existing call sites compile.
  `TransferRequest` gained `ReferenceID`.
- **`Transaction` (GET) fields follow the gateway DTO**: removed `Direction`,
  `BlockNumber`, `Confirmations` (never returned by the gateway); added
  `RiskScore`, `RiskLevel`.
- **x402 response types follow the gateway DTOs** (camelCase facilitator fields):
  - `X402SettleResponse`: `Error` → `ErrorReason` (`errorReason`)
  - `X402SettleStatusResponse`: now `{success, txId, status, txHash, network}`
    (was `tx_id` / `tx_hash`)
  - `X402Settlement`: now `{tx_id, chain, from_address, to_address, amount,
    status, valid_before, signature_v/r/s, created_at}` (removed
    `settlement_id`, `x402_nonce`)
  - `X402ListSettlements(ctx, page, pageSize)` → `X402ListSettlements(ctx,
    *ListX402SettlementsRequest)` with the `status` filter the gateway supports.
- **Webhook event constants**: removed `EventX402SettlementFailed` (never
  emitted); added `EventTransferCredited` (`transfer.credited`).
- `ErrorBody` / `APIError` moved to `errors.go` (same package, no import change).
- **Default HTTP timeout is 200s (`paratro.DefaultTimeout`), was a hard-coded
  30s.** `PROGRAM_CALL` / `CONTRACT_CALL` are synchronous: the gateway's
  engine budget is 120s, it waits 150s (budget + 30s broadcast margin) for the
  engine before answering `202`, and its server write timeout closes the
  connection at 180s. A client that gives up before the gateway loses the
  `tx_id`, so the default sits above the write timeout. Set `Config.Timeout`
  to change it, and keep it (and your context deadline) ≥ 200s for those two
  operations.

### Added

- `Transaction.CreateTransaction(ctx, req, opts...)` - the unified entry
  `POST /api/v1/transactions` with three request types:
  - `TransferRequest` (`operation=TRANSFER`): `from_address, to_address, chain,
    token_symbol, amount, memo, reference_id`
  - `ProgramCallRequest` (`operation=PROGRAM_CALL`): `from_address, chain,
    signed_transaction, receive_address?, reference_id, memo`
  - `ContractCallRequest` (`operation=CONTRACT_CALL`): `from_address, chain,
    receive_address?, contract_call{quote_id, expiration, incoming{to,token,amount},
    outgoing{from,to,token,amount}, counterparty_signature, permit_deadline?},
    reference_id, memo`
  Field names equal the JSON names; `json.Marshal(req)` yields the wire body.
- `CreateTransactionResponse{TxID, Status, Message, TxHash, HTTPStatus, Operation}`
  with `Accepted()` for the 202 "outcome unknown" answer (poll by `tx_id`; never
  resubmit). `Operation` is SDK-filled; `Accepted()` is also true for a
  `PROGRAM_CALL` / `CONTRACT_CALL` answered `200 status=PENDING`, which is how
  an `Idempotency-Key` replay of a 202 arrives.
- `Config.Timeout` and `paratro.DefaultTimeout` (200s). The per-call context
  deadline now also covers the `POST /auth/token` the SDK makes for that call.
- Constants `OperationTransfer / OperationProgramCall / OperationContractCall`,
  `StatusPending / StatusBroadcast`.
- Error model: `Code*` / `Type*` constants for the gateway's
  `{code,type,message}`; `(*APIError).ReasonTag()`, `RejectionReason(err)`,
  `IsRejected(err)` for `400 "Rejected: <tag>: …"`; `Reason*` constants for
  every tag the gateway's verifiers emit and for every engine verdict behind
  `400 transaction_failed "<OPERATION> failed: <tag>"` (the 24 `syncsettle`
  literals such as `ReasonRequestDigestMismatch` / `ReasonReceiverNotOurs` and
  the CONTRACT_CALL permit step's `ReasonPermitOwnerMismatch`,
  `ReasonPermitSpenderMismatch`, `ReasonPermitValueMismatch`,
  `ReasonPermitDigestMismatch`, `ReasonPermitDigestMissing`,
  `ReasonPermitDomainMismatch`, `ReasonPermitDomainUnverified`,
  `ReasonPermitParamsInvalid`, `ReasonPermitTokenMismatch`,
  `ReasonPermitTokenNotRegistered` — same 38-value set as the Python and Rust
  SDKs; the vocabulary is not closed); classifiers `IsForbidden` (403),
  `IsNotFound` (404), `IsServiceUnavailable` (503), `IsEndpointRetired` (410),
  `IsTokenExpired`, `IsDuplicateReferenceID`, `IsInsufficientBalance`,
  `IsTransactionFailed`, `IsAddressBlacklisted` (403 `address_blacklisted` on
  a TRANSFER to a blacklisted destination — same status as "no policy",
  different code).
- Auth: on `401 token_expired` the SDK invalidates the cached JWT, fetches a new
  one and retries the call once. Auth failures are now `*APIError` too.
- `WithIdempotencyKey(key)` request option (`Idempotency-Key` header, honoured
  by `POST /transactions` and `POST /x402/settle`).
- Redirects (3xx) are never followed - credentials and payloads are bound to
  the configured base URL.
- Contract tests against a fake gateway (`client_contract_test.go`) that pin
  the wire format of all three operations, 202 parsing, reason-tag extraction,
  410 mapping, the `CreateTransfer` wrapper path and the token-expired retry;
  timeout tests (`client_timeout_test.go`, incl. a 35s slow-gateway case that
  is skipped with `-short`); a docs guard (`docs_guard_test.go`) that fails if
  any shipped doc or comment promises a same-`reference_id` retry.
- `examples/operations`: TRANSFER / PROGRAM_CALL / CONTRACT_CALL, 202 handling,
  reason-tag handling.

### Migration 1.7 → 1.8.1

The import path does not change: `import paratro "github.com/paratro/paratro-sdk-go"`.

| 1.7 | 1.8.1 |
|---|---|
| `client.X402.X402Sign(...)` | removed - endpoint retired (410); no replacement |
| `client.Transaction.CreateTransfer(ctx, &CreateTransferRequest{...})` | unchanged call, now hits `POST /transactions` `operation=TRANSFER`; or `CreateTransaction(ctx, &TransferRequest{...})` |
| `client.X402.X402ListSettlements(ctx, 1, 20)` | `client.X402.X402ListSettlements(ctx, &ListX402SettlementsRequest{Page: 1, PageSize: 20})` |
| `settle.Error` | `settle.ErrorReason` |
| `settlement.SettlementID` / `.Nonce` | `settlement.TxID` / removed |
| `tx.Direction`, `tx.BlockNumber`, `tx.Confirmations` | removed (use `tx.TransactionType`; block data comes via webhooks) |
| `EventX402SettlementFailed` | removed |
| `apiErr.HTTPStatus == 403` etc. | still works; classifiers `IsForbidden` / `IsServiceUnavailable` / `IsEndpointRetired` added |

Notes:

- `reference_id` is per-client unique and its unique key ignores status:
  reuse → `400 Duplicate reference_id` (`IsDuplicateReferenceID`). The gateway
  raises "engine busy" (503), the engine verdict (400 `transaction_failed`) and
  the CONTRACT_CALL post-sign rejection (400 `Rejected`) after the row was
  created, and the row keeps the `reference_id`. A retry therefore always uses
  a **new** `reference_id`. On a `202` poll `GetTransaction(tx_id)` and never
  resubmit; on a transport failure replay the identical request (same
  `reference_id` / `Idempotency-Key`) rather than sending a new one. See
  [docs/error-handling.md → Retrying](docs/error-handling.md#retrying).
- `PROGRAM_CALL` / `CONTRACT_CALL` require an `OPERATION_RULES` policy on the
  client (portal → Policies). Without one every such call is `403`.

## 1.7.0 and earlier

See the git history.

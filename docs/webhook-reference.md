# Webhook Reference (Go SDK 2.x)

Paratro delivers events as `POST <your url>` with a JSON body and these headers:

| Header | Value |
|---|---|
| `X-Paratro-Timestamp` | unix seconds used in the signature |
| `X-Paratro-Signature` | `v1=` + hex(HMAC-SHA256(secret, `"<timestamp>.<raw body>"`)) |
| `X-Paratro-Signature-Version` | `v1` |
| `X-Paratro-Event-Id` | same as `event_id` in the body; use it to de-duplicate retries |

## Verify and parse

```go
err := paratro.VerifyWebhookSignature(secret, r.Header.Get("X-Paratro-Timestamp"), body,
    r.Header.Get("X-Paratro-Signature"), paratro.DefaultWebhookTolerance) // 5 minutes
event, err := paratro.ParseWebhookEvent(body)
```

Verify against the **raw** request body before decoding it. Respond `2xx`
quickly; do the work asynchronously. Deliveries are retried, so treat
`event_id` as an idempotency key.

## Event types

| Constant | `event_type` | When |
|---|---|---|
| `EventTransactionConfirming` | `transaction.confirming` | inbound deposit observed, confirmations accumulating (`status=CONFIRMING`, `transaction_type=INBOUND`) |
| `EventTransactionConfirmed` | `transaction.confirmed` | deposit, or an outbound transaction created through `POST /transactions` (TRANSFER / PROGRAM_CALL / CONTRACT_CALL), reached the required confirmations (`status=CONFIRMED`) |
| `EventTransactionFailed` | `transaction.failed` | outbound transaction failed on chain (`status=FAILED`) |
| `EventTransferCredited` | `transfer.credited` | a payment from another Paratro-hosted wallet was credited to your account (`transaction_type=INTERNAL`); deliberately not `transaction.confirmed` so deposit handlers do not pick it up unasked |
| `EventX402SettlementConfirmed` | `x402.settlement.confirmed` | an x402 settlement was credited to your (seller) account |

For `PROGRAM_CALL` / `CONTRACT_CALL` correlate by `source_id` == the `tx_id`
returned by `CreateTransaction`.

## Payload (`WebhookEvent`)

| JSON | Go | Notes |
|---|---|---|
| `event_id` | `EventID` | UUID |
| `event_type` | `EventType` | see above |
| `event_time` | `EventTime` | RFC 3339 |
| `source_id` | `SourceID` | `tx_id` of the transaction |
| `wallet_id`, `account_id` | `WalletID`, `AccountID` | |
| `status` | `Status` | `CONFIRMING` \| `CONFIRMED` \| `FAILED` |
| `transaction_type` | `TransactionType` | `INBOUND` \| `OUTBOUND` \| `INTERNAL` |
| `chain`, `network` | `Chain`, `Network` | `network`: `mainnet` \| `testnet` |
| `txhash` | `TxHash` | |
| `block_number` | `BlockNumber` | |
| `from`, `to` | `From`, `To` | |
| `symbol`, `contract_address` | `Symbol`, `ContractAddress` | `contract_address` empty for native tokens |
| `amount` | `Amount` | **smallest unit** (string); divide by `10^decimals` |
| `decimals` | `Decimals` | |
| `confirmations`, `required_confirmations` | `Confirmations`, `RequiredConfirmations` | |
| `created_at`, `confirmed_at` | `CreatedAt`, `ConfirmedAt` | RFC 3339; `confirmed_at` empty until confirmed |
| `risk_checked`, `risk_score`, `risk_level` | `RiskChecked`, `RiskScore`, `RiskLevel` | `risk_level` = `UNSCANNED` when not checked |
| `data` | `Data` | hex calldata or `""` |

# Task Summary: Synchronize Webhook Structure Across All SDKs and Docs

**Date:** 2026-04-08

## Objective

Synchronize the `WebhookEvent` struct/class across all SDKs (Python, Go, Rust) and documentation translations (7 languages) to match the agreed webhook payload specification.

## Key Change

Removed the internal `type` field (which carried values like `transfer`, `erc20_transfer`, etc.) from all webhook structs. The canonical field is now `transaction_type` (always `"TRANSFER"` for webhooks). Added `direction` (`INBOUND`/`OUTBOUND`) as a top-level field in the body table for all doc translations.

## Changes Made

### 1. Python SDK (`paratro-sdk-python`)
- **`paratro/models.py`** -- Removed `type` field from `WebhookEvent` dataclass, reordered fields to match spec
- **`paratro/webhook.py`** -- Removed `type=data.get("type", "")` from `parse_event()`, reordered field assignments
- **`README.md`** -- Updated WebhookEvent fields list to remove `type` and reflect new field order

### 2. Go SDK (`paratro-sdk-go`)
- **`webhook.go`** -- Removed `Type string json:"type"` from `WebhookEvent` struct, reordered fields to match spec

### 3. Rust SDK (`paratro-sdk-rust`)
- **`src/webhook.rs`** -- Removed `tx_type` field (with `#[serde(rename = "type")]`) from `WebhookEvent` struct, removed `#[serde(default)]` from `transaction_type` since it is now a required field, reordered fields

### 4. Documentation Translations (`paratro-docs`)
Updated 7 files (`zh`, `zh-Hant`, `ja`, `ko`, `vi`, `es`, `fr`):
- **Body table:** Replaced `type` row with `transaction_type` row, added `direction` row, updated status to include `FAILED`
- **Example payloads:** Replaced `"type": "transfer"` with `"transaction_type": "TRANSFER"`, added `"direction": "INBOUND"`, updated amounts to human-readable format, removed `"data"` field to match English version

## Build Verification

- Go: `gofmt -s -w .` and `go build ./...` passed
- Rust: `cargo build` passed

## Final Webhook Payload Spec (agreed)

```json
{
  "id": "uuid",
  "event_type": "transaction.confirming | transaction.confirmed | transaction.failed",
  "chain": "ethereum",
  "txhash": "0x...",
  "transaction_type": "TRANSFER",
  "direction": "INBOUND | OUTBOUND",
  "status": "CONFIRMING | CONFIRMED | FAILED",
  "from": "0x...",
  "to": "0x...",
  "symbol": "ETH",
  "amount": "0.05",
  "decimals": 18,
  "block_number": 10615745,
  "confirmations": 3,
  "required_confirmations": 12,
  "data": "0xa9059cbb...",
  "risk_score": 0
}
```

No `type` field. Only `transaction_type` (always "TRANSFER" for webhooks).

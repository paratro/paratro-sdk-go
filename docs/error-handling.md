# Error Handling (Go SDK 2.x)

Every non-2xx gateway response becomes a `*paratro.APIError`:

```go
type APIError struct {
    HTTPStatus int
    ErrorBody  // Code, Type, Message
}
```

`Code` / `Type` values are exported as `paratro.Code*` / `paratro.Type*`
constants (`CodeInvalidParam = "invalid_parameter"`, `CodeForbidden`,
`CodeResourceNotFound`, `CodeServiceUnavailable`, `CodeTokenExpired`,
`CodeInsufficientBalance`, `CodeTransactionFailed`, …).

## Classifiers

| Helper | True when |
|---|---|
| `IsRejected(err)` | 400 `invalid_parameter` with message `Rejected: <tag>: …` (PROGRAM_CALL / CONTRACT_CALL verifier or policy rejection; not on chain — but see [Retrying](#retrying): the row may exist) |
| `RejectionReason(err)` | the `<tag>` of a rejection, or of a `transaction_failed` ("`<OP> failed: <tag>`"); `""` otherwise |
| `IsDuplicateReferenceID(err)` | 400 `Duplicate reference_id: …` |
| `IsInsufficientBalance(err)` | code `insufficient_balance` |
| `IsTransactionFailed(err)` | 400 `transaction_failed` - the row exists and is `FAILED`; the engine's verifier tag (if any) is in `RejectionReason` |
| `IsForbidden(err)` | 403 - check `Code` first: `forbidden` = no `OPERATION_RULES` policy allows the operation on that chain (or, on auth, client inactive / IP not allowed); `address_blacklisted` = a TRANSFER to a blacklisted `to_address` (`IsAddressBlacklisted`) |
| `IsAddressBlacklisted(err)` | 403 code `address_blacklisted` (TRANSFER destination blacklisted) |
| `IsNotFound(err)` | 404 - address or asset does not belong to this client, token not credited yet, unknown id |
| `IsServiceUnavailable(err)` | 503 - signing engine busy, chain RPC unavailable, or operation not enabled; not on chain, but "engine busy" is raised after the row was created and the row keeps the `reference_id` — retry later with a **new** `reference_id` (see [Retrying](#retrying)) |
| `IsEndpointRetired(err)` | 410 - `POST /transfer`, `POST /x402/sign` |
| `IsTokenExpired(err)` | 401 `token_expired` after the SDK's automatic refresh + retry also expired |
| `IsAuthError(err)` | 401 or 403 |
| `IsRateLimited(err)` | 429 |

`(*APIError).IsRejected()` and `(*APIError).ReasonTag()` are the method forms.

## Rejection reason tags

A rejection message is `Rejected: <tag>: <detail>`. `<tag>` is lowercase words
joined by underscores; `<detail>` is free text for humans. Tags are exported as
`paratro.Reason*`.

Shared (both operations):

| Tag | Constant | Meaning |
|---|---|---|
| `counterparty_not_registered` | `ReasonCounterpartyNotRegistered` | destination (PROGRAM_CALL ATA owner / CONTRACT_CALL `incoming.to`, `outgoing.from`) not in `recipient_rules.counterparties` |
| `limit_per_transaction` | `ReasonLimitPerTransaction` | outgoing amount > `single_limit` |
| `limit_daily` | `ReasonLimitDaily` | daily total would exceed `daily_limit` |
| `limit_not_configured` | `ReasonLimitNotConfigured` | policy has no `single_limit` / `daily_limit` (fail closed) |
| `limit_decimals_ambiguous` | `ReasonLimitDecimalsAmbiguous` | daily limit cannot be applied because the paying token's decimals are ambiguous |

PROGRAM_CALL (Solana):

| Tag | Constant |
|---|---|
| `policy_invalid` | `ReasonPolicyInvalid` - `call_rules.allowed_programs` cannot be parsed (gateway `program_call.go`; the engine also emits it as a `transaction_failed` tag for both operations) |
| `malformed` | `ReasonMalformed` - `signed_transaction` does not decode as a Solana transaction |
| `shape` | `ReasonShape` - not the fixed 3-instruction shape / signer layout |
| `alt_not_allowed` | `ReasonALTNotAllowed` - Address Lookup Tables present |
| `program_not_allowed` | `ReasonProgramNotAllowed` - program not in `allowed_programs` |
| `program_unresolvable` | `ReasonProgramUnresolvable` |
| `account_unresolvable` | `ReasonAccountUnresolvable` |
| `ata_derivation` | `ReasonATADerivation` |
| `mint_not_registered` | `ReasonMintNotRegistered` - mint not in `allowed_mints` / not registered |
| `mint_program_unknown` | `ReasonMintProgramUnknown` |
| `outgoing_source` | `ReasonOutgoingSource` - outgoing leg does not leave your ATA |
| `outgoing_authority` | `ReasonOutgoingAuthority` - outgoing authority is not your wallet |
| `incoming_destination` | `ReasonIncomingDestination` - incoming leg does not land on `receive_address`'s ATA |
| `fee_payer` | `ReasonFeePayer` - `from_address` is not in the fee-payer slot |
| `payer_signature_present` | `ReasonPayerSignaturePresent` - your signature slot must be empty |
| `counterparty_signature_missing` | `ReasonCounterpartySignatureMissing` |
| `counterparty_signature_invalid` | `ReasonCounterpartySignatureInvalid` |

CONTRACT_CALL (EVM `executeSwap`):

| Tag | Constant |
|---|---|
| `abi`, `calldata`, `calldata_not_canonical`, `selector` | `ReasonABI`, `ReasonCalldata`, `ReasonCalldataNotCanonical`, `ReasonSelector` - calldata does not encode the registered `executeSwap` |
| `amount_not_positive` | `ReasonAmountNotPositive` |
| `contract_address` | `ReasonContractAddress` - target ≠ policy `allowed_contracts[chain]` |
| `expiration`, `expiration_passed`, `expiration_too_far` | `ReasonExpiration*` - invalid / past / > `max_execution_timeout_seconds` |
| `incoming_from` | `ReasonIncomingFrom` - `incoming.from` ≠ `from_address` |
| `outgoing_to` | `ReasonOutgoingTo` - `outgoing.to` ≠ `receive_address` |
| `payment_token_not_registered` | `ReasonPaymentTokenNotRegistered` - `incoming.token` not in `payment_tokens` |
| `target_token_not_registered` | `ReasonTargetTokenNotRegistered` - `outgoing.token` not in `target_tokens` |
| `permit_deadline`, `permit_deadline_passed`, `permit_deadline_too_far` | `ReasonPermitDeadline*` |
| `permit_owner` | `ReasonPermitOwner` - permit owner ≠ `from_address` |
| `value_not_zero` | `ReasonValueNotZero` |

### Engine failure tags (`400 transaction_failed`)

`400 transaction_failed` (`"<OPERATION> failed: <tag>"`) is the signing engine's
verdict after the row was created (`IsTransactionFailed`; the row is `FAILED`).
`RejectionReason` returns the tag. The engine re-runs the verifiers, so any tag
above can appear; on top of that the engine emits its own, all exported as
`paratro.Reason*` (same 38-value set as `RejectionReason.ENGINE_FAILURE_TAGS` in
the Python SDK and `reason_tag::ENGINE_FAILURE_TAGS` in the Rust SDK):

| Source | Tags |
|---|---|
| settle / broadcast path (`mpc-engine internal/syncsettle`, both operations) | `calldata_invalid` `contract_address_invalid` `contract_not_registered` `cosignature_invalid` `daily_allowance_missing` `daily_usage_unavailable` `internal` `mint_token_program_unresolved` `payer_invalid` `payer_mismatch` `policy_not_authorized` `receiver_invalid` `receiver_lookup_failed` `receiver_missing` `receiver_not_ours` `request_digest_mismatch` `request_digest_missing` `signer_slot` (plus `alt_not_allowed` `limit_daily` `limit_not_configured` `malformed` `policy_invalid` `program_not_allowed` by name) |
| EIP-2612 permit step of a CONTRACT_CALL (`internal/syncsign/permit.go`) | `permit_digest_mismatch` `permit_digest_missing` `permit_domain_mismatch` `permit_domain_unverified` `permit_owner_mismatch` `permit_params_invalid` `permit_spender_mismatch` `permit_token_mismatch` `permit_token_not_registered` `permit_value_mismatch` (plus `amount_not_positive` `contract_not_registered` `internal` `limit_not_configured` `limit_per_transaction` `permit_deadline_passed` `permit_deadline_too_far` `policy_invalid` `policy_not_authorized` by name) |

Internal engine errors (SQL, lock waits, TSS / broadcast failures) collapse to
`"engine rejected the transaction"` and `RejectionReason` returns `""`. The
vocabulary is not closed — a new gateway / engine release can add tags — so match
on the tags you handle and treat the rest as "failed, reason in the message".

## Retrying

What each answer says about the `reference_id` you sent (gateway
`internal/service/{operation_service,program_call,contract_call}.go`; the
`uk_client_reference (client_id, client_reference_key)` unique key ignores
status):

| Answer | Row created? | Retry |
|---|---|---|
| `200` / `202` | yes | never resubmit; `202` → poll `GetTransaction(tx_id)` |
| `400 Rejected: <tag>` | usually no; **yes** for the CONTRACT_CALL post-sign check (row held `PENDING` until the permit deadline) | new `reference_id` |
| `400 transaction_failed` | yes (`FAILED`) | new `reference_id` |
| `400 insufficient_balance`, `403`, `404` | no | fix the cause; new `reference_id` is always safe |
| `503 Signing service is busy` | **yes** — raised after the insert; row `FAILED`, or held `PENDING` for a CONTRACT_CALL whose permit was already signed | new `reference_id` (the same one → `400 Duplicate reference_id`) |
| `503 Chain RPC unavailable` / `not enabled` | no | new `reference_id` is always safe |
| transport error, no response | unknown | do not resubmit with a new `reference_id`; replay the identical request (same `reference_id`, same `Idempotency-Key`): with an `Idempotency-Key` you get the original body (2xx cached 24h under that key), otherwise `400 Duplicate reference_id` if the row exists, or a normal answer if no row was ever created |

The rule that covers every row: **a retry uses a new `reference_id`; only a
`202` and a transport failure must not be resubmitted at all.** After a
CONTRACT_CALL fails past the permit step, the previous reservation stays locked
until the permit deadline, so a retry can answer `insufficient_balance` until
then. `GET /transactions` cannot filter by `reference_id` and the transaction
DTO does not return it, so keep your own `reference_id → tx_id` record, and
keep `Config.Timeout` / the context deadline at or above `paratro.DefaultTimeout`
(200s — above the gateway's 150s engine wait and 180s write timeout) for
`PROGRAM_CALL` / `CONTRACT_CALL` so a slow engine ends in a `202` with a
`tx_id` rather than in a client-side timeout without one.

## Pattern

```go
resp, err := client.Transaction.CreateTransaction(ctx, req)
if err != nil {
    switch {
    case paratro.IsRejected(err):
        switch paratro.RejectionReason(err) {
        case paratro.ReasonExpirationPassed, paratro.ReasonPermitDeadlinePassed:
            // refresh the quote and try again with a NEW reference_id
        case paratro.ReasonLimitDaily:
            // wait for the next day / raise the policy limit
        default:
            // configuration problem: log the full message
        }
    case paratro.IsDuplicateReferenceID(err):
        // this reference_id already has a row (a previous attempt, possibly a
        // failed one): do not resubmit it; use a new reference_id if you still
        // want the operation
    case paratro.IsServiceUnavailable(err):
        // back off and retry with a NEW reference_id (engine busy leaves a
        // FAILED row that keeps the old one)
    case paratro.IsAddressBlacklisted(err):
        // TRANSFER destination blacklisted
    case paratro.IsForbidden(err), paratro.IsNotFound(err):
        // setup problem (policy / account / asset)
    default:
        var apiErr *paratro.APIError
        if errors.As(err, &apiErr) {
            log.Printf("%d %s: %s", apiErr.HTTPStatus, apiErr.Code, apiErr.Message)
        }
    }
    return
}
if resp.Accepted() {
    // 202 (or its Idempotency-Key replay as 200 PENDING): poll
    // GetTransaction(resp.TxID); never resubmit
}
```

## Non-API errors

Transport failures, JSON decode failures and the SDK's own argument checks
(`nil` request, empty id) are plain errors wrapped with `%w`; none of the
classifiers match them. Auth failures on `POST /auth/token` are `*APIError`
wrapped in `failed to get JWT token: …`. A client-side timeout on
`CreateTransaction` is a transport failure: see [Retrying](#retrying) — you
have no `tx_id`, treat it like a `202`.

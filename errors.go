package paratro

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ErrorBody is the gateway's error response body: {"code","type","message"}.
type ErrorBody struct {
	Code    string `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// APIError is returned for every non-2xx gateway response. HTTPStatus carries
// the HTTP status; Code / Type / Message are the gateway's error body.
type APIError struct {
	HTTPStatus int
	ErrorBody
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("API error: %s - %s (type: %s, http_status: %d)",
		e.Code, e.Message, e.Type, e.HTTPStatus)
}

// Error codes returned in ErrorBody.Code (gateway common/errors.go).
const (
	CodeBadRequest          = "bad_request"
	CodeInvalidParam        = "invalid_parameter"
	CodeValidationFailed    = "validation_failed"
	CodeUnauthorized        = "unauthorized"
	CodeInvalidToken        = "invalid_token"
	CodeTokenExpired        = "token_expired"
	CodeForbidden           = "forbidden"
	CodeNotFound            = "not_found"
	CodeResourceNotFound    = "resource_not_found"
	CodeConflict            = "conflict"
	CodeResourceExists      = "resource_exists"
	CodeTooManyRequests     = "too_many_requests"
	CodeInternalError       = "internal_error"
	CodeDatabaseError       = "database_error"
	CodeCacheError          = "cache_error"
	CodeServiceUnavailable  = "service_unavailable"
	CodeBusinessError       = "business_error"
	CodeWalletLimitReached  = "wallet_limit_reached"
	CodeAccountLimitReached = "account_limit_reached"
	CodeChainNotAllowed     = "chain_not_allowed"
	CodeWithdrawalLimited   = "withdrawal_limit_reached"
	CodeAPIQuotaExceeded    = "api_quota_exceeded"
	CodeInsufficientBalance = "insufficient_balance"
	CodeInvalidAddress      = "invalid_address"
	CodeTransactionFailed   = "transaction_failed"
	CodeConcurrencyError    = "concurrency_error"
	CodeAssetAlreadyExists  = "asset_already_exists"
	CodeWalletNotActive     = "wallet_not_active"
	CodeAccountNotActive    = "account_not_active"
	CodeAddressBlacklisted  = "address_blacklisted"
)

// Error types returned in ErrorBody.Type.
const (
	TypeInvalidRequest  = "invalid_request_error"
	TypeAuthentication  = "authentication_error"
	TypePermission      = "permission_error"
	TypeNotFound        = "not_found_error"
	TypeConflict        = "conflict_error"
	TypeRateLimit       = "rate_limit_error"
	TypeAPI             = "api_error"
	TypeBusiness        = "business_error"
	TypeEndpointRetired = "endpoint_retired" // HTTP 410, see IsEndpointRetired
)

// ReasonTag is the machine-readable tag at the front of a PROGRAM_CALL /
// CONTRACT_CALL rejection ("Rejected: <tag>: <detail>", HTTP 400,
// code=invalid_parameter) or of an engine verdict ("<OPERATION> failed: <tag>",
// HTTP 400, code=transaction_failed). Extract it with (*APIError).ReasonTag or
// RejectionReason.
//
// The Reason* constants below are every tag literal in the gateway, verifier
// and engine code at the time of this release (gateway develop @ b8bbea5,
// paratro-common xchange, mpc-engine develop @ 3d4a0ed). The vocabulary is not
// closed: a new gateway / engine release can add tags, and TSS / broadcast
// failures arrive without one ("engine rejected the transaction"). Match on
// the tags you handle and treat an unknown tag as a rejection you have not seen
// yet. Same values as RejectionReason in the Python SDK and
// paratro_sdk::reason_tag in the Rust SDK.
type ReasonTag = string

// Rejection reason tags shared by PROGRAM_CALL and CONTRACT_CALL.
const (
	ReasonCounterpartyNotRegistered ReasonTag = "counterparty_not_registered"
	ReasonLimitPerTransaction       ReasonTag = "limit_per_transaction"
	ReasonLimitDaily                ReasonTag = "limit_daily"
	ReasonLimitNotConfigured        ReasonTag = "limit_not_configured"
	ReasonLimitDecimalsAmbiguous    ReasonTag = "limit_decimals_ambiguous"
)

// Rejection reason tags specific to PROGRAM_CALL (Solana).
const (
	// ReasonPolicyInvalid: as a 400 "Rejected:" tag the gateway emits it only
	// for PROGRAM_CALL (internal/service/program_call.go, unparseable
	// call_rules.allowed_programs). The engine also uses it as a
	// transaction_failed tag for both operations (syncsettle/operation.go,
	// syncsign/permit.go) when a policy list cannot be parsed.
	ReasonPolicyInvalid                ReasonTag = "policy_invalid"
	ReasonMalformed                    ReasonTag = "malformed"
	ReasonShape                        ReasonTag = "shape"
	ReasonALTNotAllowed                ReasonTag = "alt_not_allowed"
	ReasonProgramNotAllowed            ReasonTag = "program_not_allowed"
	ReasonProgramUnresolvable          ReasonTag = "program_unresolvable"
	ReasonAccountUnresolvable          ReasonTag = "account_unresolvable"
	ReasonATADerivation                ReasonTag = "ata_derivation"
	ReasonMintNotRegistered            ReasonTag = "mint_not_registered"
	ReasonMintProgramUnknown           ReasonTag = "mint_program_unknown"
	ReasonOutgoingSource               ReasonTag = "outgoing_source"
	ReasonOutgoingAuthority            ReasonTag = "outgoing_authority"
	ReasonIncomingDestination          ReasonTag = "incoming_destination"
	ReasonFeePayer                     ReasonTag = "fee_payer"
	ReasonPayerSignaturePresent        ReasonTag = "payer_signature_present"
	ReasonCounterpartySignatureMissing ReasonTag = "counterparty_signature_missing"
	ReasonCounterpartySignatureInvalid ReasonTag = "counterparty_signature_invalid"
)

// Rejection reason tags specific to CONTRACT_CALL (EVM executeSwap).
const (
	ReasonABI                       ReasonTag = "abi"
	ReasonAmountNotPositive         ReasonTag = "amount_not_positive"
	ReasonCalldata                  ReasonTag = "calldata"
	ReasonCalldataNotCanonical      ReasonTag = "calldata_not_canonical"
	ReasonContractAddress           ReasonTag = "contract_address"
	ReasonExpiration                ReasonTag = "expiration"
	ReasonExpirationPassed          ReasonTag = "expiration_passed"
	ReasonExpirationTooFar          ReasonTag = "expiration_too_far"
	ReasonIncomingFrom              ReasonTag = "incoming_from"
	ReasonOutgoingTo                ReasonTag = "outgoing_to"
	ReasonPaymentTokenNotRegistered ReasonTag = "payment_token_not_registered"
	ReasonTargetTokenNotRegistered  ReasonTag = "target_token_not_registered"
	ReasonPermitDeadline            ReasonTag = "permit_deadline"
	ReasonPermitDeadlinePassed      ReasonTag = "permit_deadline_passed"
	ReasonPermitDeadlineTooFar      ReasonTag = "permit_deadline_too_far"
	ReasonPermitOwner               ReasonTag = "permit_owner"
	ReasonSelector                  ReasonTag = "selector"
	ReasonValueNotZero              ReasonTag = "value_not_zero"
)

// Engine failure tags: the signing engine's verdict after the transaction row
// was created, surfaced as 400 code=transaction_failed "<OPERATION> failed:
// <tag>" (IsTransactionFailed). These are every reject("…") literal in
// mpc-engine internal/syncsettle (settle / broadcast path of both operations)
// plus every rejectPermit("…") literal in internal/syncsign/permit.go (the
// EIP-2612 permit a CONTRACT_CALL signs first). The engine also re-runs the
// paratro-common verifiers, so any Rejected tag above can appear here as well;
// the ones it emits by name (alt_not_allowed, amount_not_positive, limit_daily,
// limit_not_configured, limit_per_transaction, malformed, permit_deadline_passed,
// permit_deadline_too_far, policy_invalid, program_not_allowed) are already
// declared above and are not repeated.
const (
	ReasonCalldataInvalid            ReasonTag = "calldata_invalid"
	ReasonContractAddressInvalid     ReasonTag = "contract_address_invalid"
	ReasonContractNotRegistered      ReasonTag = "contract_not_registered"
	ReasonCosignatureInvalid         ReasonTag = "cosignature_invalid"
	ReasonDailyAllowanceMissing      ReasonTag = "daily_allowance_missing"
	ReasonDailyUsageUnavailable      ReasonTag = "daily_usage_unavailable"
	ReasonInternal                   ReasonTag = "internal"
	ReasonMintTokenProgramUnresolved ReasonTag = "mint_token_program_unresolved"
	ReasonPayerInvalid               ReasonTag = "payer_invalid"
	ReasonPayerMismatch              ReasonTag = "payer_mismatch"
	ReasonPolicyNotAuthorized        ReasonTag = "policy_not_authorized"
	ReasonReceiverInvalid            ReasonTag = "receiver_invalid"
	ReasonReceiverLookupFailed       ReasonTag = "receiver_lookup_failed"
	ReasonReceiverMissing            ReasonTag = "receiver_missing"
	ReasonReceiverNotOurs            ReasonTag = "receiver_not_ours"
	ReasonRequestDigestMismatch      ReasonTag = "request_digest_mismatch"
	ReasonRequestDigestMissing       ReasonTag = "request_digest_missing"
	ReasonSignerSlot                 ReasonTag = "signer_slot"
)

// Engine failure tags of the CONTRACT_CALL permit step (mpc-engine
// internal/syncsign/permit.go): the engine re-derives the EIP-2612 permit from
// the row and the policy before signing it and refuses when its view differs
// from the gateway's request.
const (
	ReasonPermitDigestMismatch     ReasonTag = "permit_digest_mismatch"
	ReasonPermitDigestMissing      ReasonTag = "permit_digest_missing"
	ReasonPermitDomainMismatch     ReasonTag = "permit_domain_mismatch"
	ReasonPermitDomainUnverified   ReasonTag = "permit_domain_unverified"
	ReasonPermitOwnerMismatch      ReasonTag = "permit_owner_mismatch"
	ReasonPermitParamsInvalid      ReasonTag = "permit_params_invalid"
	ReasonPermitSpenderMismatch    ReasonTag = "permit_spender_mismatch"
	ReasonPermitTokenMismatch      ReasonTag = "permit_token_mismatch"
	ReasonPermitTokenNotRegistered ReasonTag = "permit_token_not_registered"
	ReasonPermitValueMismatch      ReasonTag = "permit_value_mismatch"
)

const rejectedPrefix = "Rejected: "

// reasonTagPattern mirrors the gateway's engineReasonTag: lowercase words
// joined by underscores.
var reasonTagPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

// IsRejected reports whether the error is a 400 "Rejected: <tag>: …" policy /
// verifier rejection of a PROGRAM_CALL or CONTRACT_CALL. The request did not
// reach the chain. It does NOT mean nothing was stored: the gateway's
// CONTRACT_CALL post-sign check rejects after the transaction row was created,
// and that row keeps the reference_id (see CreateTransaction). Retry with a new
// reference_id.
func (e *APIError) IsRejected() bool {
	return e != nil && e.HTTPStatus == http.StatusBadRequest &&
		e.Code == CodeInvalidParam && strings.HasPrefix(e.Message, rejectedPrefix)
}

// ReasonTag returns the machine-readable reason tag of a rejection, or "" when
// the error carries none.
//
// Two gateway messages carry a tag:
//
//	400 invalid_parameter   "Rejected: <tag>: <detail>"   → <tag>
//	400 transaction_failed  "<OPERATION> failed: <tag>"    → <tag> (engine verdict after the row was created)
//
// For transaction_failed the gateway collapses internal errors to the phrase
// "engine rejected the transaction", which is not a tag and yields "".
func (e *APIError) ReasonTag() ReasonTag {
	if e == nil {
		return ""
	}
	var rest string
	switch {
	case e.IsRejected():
		rest = strings.TrimPrefix(e.Message, rejectedPrefix)
	case e.Code == CodeTransactionFailed:
		_, after, ok := strings.Cut(e.Message, " failed: ")
		if !ok {
			return ""
		}
		rest = after
	default:
		return ""
	}
	tag := rest
	if i := strings.Index(tag, ":"); i >= 0 {
		tag = tag[:i]
	}
	tag = strings.TrimSpace(tag)
	if reasonTagPattern.MatchString(tag) {
		return tag
	}
	return ""
}

func asAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		return apiErr, true
	}
	return nil, false
}

// IsNotFound reports whether the error is a 404 response (address / asset does
// not belong to this client, token not yet credited, unknown tx_id, …).
func IsNotFound(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusNotFound
}

// IsForbidden reports whether the error is a 403 response. Look at Code before
// deciding what it means:
//
//	code=forbidden            PROGRAM_CALL / CONTRACT_CALL: no OPERATION_RULES policy
//	                          allows the operation on that chain; or, on auth,
//	                          client inactive / caller IP not allowed
//	code=address_blacklisted  TRANSFER: the destination address is blacklisted
//	                          (IsAddressBlacklisted) — not a policy problem
func IsForbidden(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusForbidden
}

// IsAddressBlacklisted reports whether the error is the 403
// code=address_blacklisted a TRANSFER gets when to_address is blacklisted.
func IsAddressBlacklisted(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.Code == CodeAddressBlacklisted
}

// IsServiceUnavailable reports whether the error is a 503 response: signing
// engine busy, chain RPC unavailable, or the operation is not enabled on this
// gateway. The request did not reach the chain, but "engine busy" is raised
// AFTER the transaction row was created (the gateway marks it FAILED, or holds
// it PENDING until the permit deadline for a CONTRACT_CALL whose permit was
// already signed) and the row keeps the reference_id. Retrying with the same
// reference_id therefore gets 400 Duplicate reference_id; retry with a new
// one. See CreateTransaction.
func IsServiceUnavailable(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusServiceUnavailable
}

// IsEndpointRetired reports whether the error is a 410 response from a retired
// endpoint (POST /api/v1/transfer, POST /api/v1/x402/sign). The message names
// the replacement.
func IsEndpointRetired(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusGone
}

// IsRateLimited reports whether the error is a 429 Too Many Requests response.
func IsRateLimited(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusTooManyRequests
}

// IsAuthError reports whether the error is an authentication/authorization error (401 or 403).
func IsAuthError(err error) bool {
	e, ok := asAPIError(err)
	return ok && (e.HTTPStatus == http.StatusUnauthorized || e.HTTPStatus == http.StatusForbidden)
}

// IsTokenExpired reports whether the error is a 401 code=token_expired. The
// SDK refreshes the token and retries once on its own, so callers normally see
// this only when the retry also expired.
func IsTokenExpired(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusUnauthorized && e.Code == CodeTokenExpired
}

// IsRejected reports whether the error is a 400 "Rejected: <tag>: …" policy /
// verifier rejection. Use RejectionReason to get the tag.
func IsRejected(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.IsRejected()
}

// RejectionReason returns the reason tag of a rejection (see
// (*APIError).ReasonTag), or "" if err carries none.
func RejectionReason(err error) ReasonTag {
	e, ok := asAPIError(err)
	if !ok {
		return ""
	}
	return e.ReasonTag()
}

// IsDuplicateReferenceID reports whether the error is the 400 returned when
// the same client reuses a reference_id ("Duplicate reference_id: …").
func IsDuplicateReferenceID(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.HTTPStatus == http.StatusBadRequest && e.Code == CodeInvalidParam &&
		strings.HasPrefix(e.Message, "Duplicate reference_id")
}

// IsInsufficientBalance reports whether the error is a 400 code=insufficient_balance.
func IsInsufficientBalance(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.Code == CodeInsufficientBalance
}

// IsTransactionFailed reports whether the error is a 400 code=transaction_failed:
// the transaction row was created and the signing engine then failed it. The
// engine's machine-readable reason, if any, is available via RejectionReason.
func IsTransactionFailed(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.Code == CodeTransactionFailed
}

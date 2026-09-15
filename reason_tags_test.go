package paratro

import "testing"

// engineFailureTags mirrors RejectionReason.ENGINE_FAILURE_TAGS (Python) and
// reason_tag::ENGINE_FAILURE_TAGS (Rust): every reject("…") literal in mpc-engine
// internal/syncsettle plus every rejectPermit("…") literal in
// internal/syncsign/permit.go — 24 + 14 = 38 values. The three SDKs must stay
// identical; change all of them together.
var engineFailureTags = []ReasonTag{
	ReasonALTNotAllowed,
	ReasonAmountNotPositive,
	ReasonCalldataInvalid,
	ReasonContractAddressInvalid,
	ReasonContractNotRegistered,
	ReasonCosignatureInvalid,
	ReasonDailyAllowanceMissing,
	ReasonDailyUsageUnavailable,
	ReasonInternal,
	ReasonLimitDaily,
	ReasonLimitNotConfigured,
	ReasonLimitPerTransaction,
	ReasonMalformed,
	ReasonMintTokenProgramUnresolved,
	ReasonPayerInvalid,
	ReasonPayerMismatch,
	ReasonPermitDeadlinePassed,
	ReasonPermitDeadlineTooFar,
	ReasonPermitDigestMismatch,
	ReasonPermitDigestMissing,
	ReasonPermitDomainMismatch,
	ReasonPermitDomainUnverified,
	ReasonPermitOwnerMismatch,
	ReasonPermitParamsInvalid,
	ReasonPermitSpenderMismatch,
	ReasonPermitTokenMismatch,
	ReasonPermitTokenNotRegistered,
	ReasonPermitValueMismatch,
	ReasonPolicyInvalid,
	ReasonPolicyNotAuthorized,
	ReasonProgramNotAllowed,
	ReasonReceiverInvalid,
	ReasonReceiverLookupFailed,
	ReasonReceiverMissing,
	ReasonReceiverNotOurs,
	ReasonRequestDigestMismatch,
	ReasonRequestDigestMissing,
	ReasonSignerSlot,
}

func TestEngineFailureTagsPinTheEngineLiterals(t *testing.T) {
	if len(engineFailureTags) != 38 {
		t.Fatalf("expected 38 engine failure tags, got %d", len(engineFailureTags))
	}
	seen := map[ReasonTag]bool{}
	for _, tag := range engineFailureTags {
		if seen[tag] {
			t.Errorf("duplicate engine failure tag %q", tag)
		}
		seen[tag] = true
		// Same shape the gateway's publicEngineReason forwards.
		if !reasonTagPattern.MatchString(tag) || len(tag) > 64 {
			t.Errorf("tag %q does not have the gateway's reason-tag shape", tag)
		}
	}
	for _, permitTag := range []ReasonTag{
		ReasonPermitDigestMismatch, ReasonPermitDigestMissing, ReasonPermitDomainMismatch,
		ReasonPermitDomainUnverified, ReasonPermitOwnerMismatch, ReasonPermitParamsInvalid,
		ReasonPermitSpenderMismatch, ReasonPermitTokenMismatch, ReasonPermitTokenNotRegistered,
		ReasonPermitValueMismatch,
	} {
		if !seen[permitTag] {
			t.Errorf("syncsign permit tag %q missing from the engine failure set", permitTag)
		}
	}

	// The tag reaches the caller through the transaction_failed message.
	err := &APIError{HTTPStatus: 400, ErrorBody: ErrorBody{
		Code: CodeTransactionFailed, Type: TypeBusiness,
		Message: "CONTRACT_CALL failed: permit_owner_mismatch: row from_address 0x… : mismatch",
	}}
	if got := RejectionReason(err); got != ReasonPermitOwnerMismatch {
		t.Errorf("RejectionReason = %q, want %q", got, ReasonPermitOwnerMismatch)
	}
	if !IsTransactionFailed(err) || IsRejected(err) {
		t.Errorf("transaction_failed must be IsTransactionFailed and not IsRejected")
	}
}

package paratro

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Contract tests: a loopback httptest server plays the gateway. Nothing here
// talks to a real environment; the credentials are fixtures.

type recordedRequest struct {
	Method  string
	Path    string
	RawPath string
	Query   string
	Headers http.Header
	Body    []byte
}

// contractClient starts a fake gateway. /api/v1/auth/token is served by the
// fixture (counting calls); everything else goes to handler.
func contractClient(t *testing.T, handler http.HandlerFunc) (*MPCClient, *atomic.Int32) {
	t.Helper()
	var authCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/auth/token" {
			authCalls.Add(1)
			if r.Method != http.MethodPost || r.Header.Get("X-API-Key") != "fixture-key" || r.Header.Get("X-API-Secret") != "fixture-secret" {
				t.Error("auth request did not carry X-API-Key / X-API-Secret via POST")
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("auth request must not carry a bearer token")
			}
			n := authCalls.Load()
			_, _ = fmt.Fprintf(w, `{"token":"jwt-%d","expires_in":900,"token_type":"Bearer","client":{"client_id":"c1"}}`, n)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer jwt-") {
			t.Errorf("business request lacks bearer token: %q", r.Header.Get("Authorization"))
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := NewMPCClient("fixture-key", "fixture-secret", Custom(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c, &authCalls
}

// recordingClient captures every business request and answers with status/body.
func recordingClient(t *testing.T, status int, body string) (*MPCClient, *[]recordedRequest) {
	t.Helper()
	var seen []recordedRequest
	c, _ := contractClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen = append(seen, recordedRequest{
			Method: r.Method, Path: r.URL.Path, RawPath: r.URL.EscapedPath(), Query: r.URL.RawQuery,
			Headers: r.Header.Clone(), Body: raw,
		})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	return c, &seen
}

func errBody(code, typ, msg string) string {
	b, _ := json.Marshal(ErrorBody{Code: code, Type: typ, Message: msg})
	return string(b)
}

// ── POST /api/v1/transactions: wire format ──────────────────────────────────

func TestCreateTransactionWireFormat(t *testing.T) {
	cases := []struct {
		name     string
		req      TransactionRequest
		wantJSON string
	}{
		{
			name: "TRANSFER",
			req: &TransferRequest{
				FromAddress: "0xfrom", ToAddress: "0xto", Chain: "ethereum",
				TokenSymbol: "USDT", Amount: "10.5", Memo: "invoice 7", ReferenceID: "ord-1",
			},
			wantJSON: `{"operation":"TRANSFER","reference_id":"ord-1","from_address":"0xfrom","chain":"ethereum","memo":"invoice 7","to_address":"0xto","token_symbol":"USDT","amount":"10.5"}`,
		},
		{
			name: "TRANSFER minimal",
			req: TransferRequest{
				FromAddress: "0xfrom", ToAddress: "0xto", Chain: "ethereum", TokenSymbol: "ETH", Amount: "0.000000000000000001",
			},
			wantJSON: `{"operation":"TRANSFER","from_address":"0xfrom","chain":"ethereum","to_address":"0xto","token_symbol":"ETH","amount":"0.000000000000000001"}`,
		},
		{
			name: "PROGRAM_CALL",
			req: &ProgramCallRequest{
				FromAddress: "Payer1111111111111111111111111111111111111", Chain: "solana",
				SignedTransaction: "AQIDBA==", ReceiveAddress: "Recv11111111111111111111111111111111111111",
				ReferenceID: "quote-42",
			},
			wantJSON: `{"operation":"PROGRAM_CALL","reference_id":"quote-42","from_address":"Payer1111111111111111111111111111111111111","chain":"solana","receive_address":"Recv11111111111111111111111111111111111111","signed_transaction":"AQIDBA=="}`,
		},
		{
			name: "PROGRAM_CALL default receive_address",
			req: ProgramCallRequest{
				FromAddress: "Payer1111111111111111111111111111111111111", Chain: "solana", SignedTransaction: "0x0102",
			},
			wantJSON: `{"operation":"PROGRAM_CALL","from_address":"Payer1111111111111111111111111111111111111","chain":"solana","signed_transaction":"0x0102"}`,
		},
		{
			name: "CONTRACT_CALL",
			req: &ContractCallRequest{
				FromAddress: "0x96586e99CE724F45bAb65cf963533b810147c1F4", Chain: "ethereum",
				ReceiveAddress: "0x96586e99CE724F45bAb65cf963533b810147c1F4",
				ReferenceID:    "quote-0xabc", Memo: "optional",
				ContractCall: ContractCall{
					QuoteID:    "0x" + strings.Repeat("ab", 32),
					Expiration: 1789449058,
					Incoming:   ContractCallIncomingLeg{To: "0xcf8a", Token: "0x59fb", Amount: "10000000"},
					Outgoing: ContractCallOutgoingLeg{
						From: "0xcf8a", To: "0x9658", Token: "0xa55a", Amount: "42000000000000000",
					},
					CounterpartySignature: "0x" + strings.Repeat("11", 65),
					PermitDeadline:        1789449358,
				},
			},
			wantJSON: `{"operation":"CONTRACT_CALL","reference_id":"quote-0xabc","from_address":"0x96586e99CE724F45bAb65cf963533b810147c1F4","chain":"ethereum","memo":"optional","receive_address":"0x96586e99CE724F45bAb65cf963533b810147c1F4","contract_call":{"quote_id":"0x` + strings.Repeat("ab", 32) + `","expiration":1789449058,"incoming":{"to":"0xcf8a","token":"0x59fb","amount":"10000000"},"outgoing":{"from":"0xcf8a","to":"0x9658","token":"0xa55a","amount":"42000000000000000"},"counterparty_signature":"0x` + strings.Repeat("11", 65) + `","permit_deadline":1789449358}}`,
		},
		{
			name: "CONTRACT_CALL default permit_deadline",
			req: ContractCallRequest{
				FromAddress: "0xpayer", Chain: "ethereum",
				ContractCall: ContractCall{
					QuoteID: "ab", Expiration: 1,
					Incoming:              ContractCallIncomingLeg{To: "0x1", Token: "0x2", Amount: "3"},
					Outgoing:              ContractCallOutgoingLeg{From: "0x1", To: "0xpayer", Token: "0x4", Amount: "5"},
					CounterpartySignature: "0x6",
				},
			},
			wantJSON: `{"operation":"CONTRACT_CALL","from_address":"0xpayer","chain":"ethereum","contract_call":{"quote_id":"ab","expiration":1,"incoming":{"to":"0x1","token":"0x2","amount":"3"},"outgoing":{"from":"0x1","to":"0xpayer","token":"0x4","amount":"5"},"counterparty_signature":"0x6"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, seen := recordingClient(t, http.StatusOK, `{"tx_id":"tx-1","status":"PENDING","message":"ok"}`)
			if _, err := c.Transaction.CreateTransaction(context.Background(), tc.req); err != nil {
				t.Fatal(err)
			}
			if len(*seen) != 1 {
				t.Fatalf("expected exactly one request, got %d", len(*seen))
			}
			got := (*seen)[0]
			if got.Method != http.MethodPost || got.Path != "/api/v1/transactions" || got.Query != "" {
				t.Errorf("wrong route: %s %s?%s", got.Method, got.Path, got.Query)
			}
			if got.Headers.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q", got.Headers.Get("Content-Type"))
			}
			if string(got.Body) != tc.wantJSON {
				t.Errorf("body mismatch\n got: %s\nwant: %s", got.Body, tc.wantJSON)
			}
			// json.Marshal on the request itself yields the same wire body.
			direct, err := json.Marshal(tc.req)
			if err != nil || string(direct) != tc.wantJSON {
				t.Errorf("json.Marshal(request) = %s, %v", direct, err)
			}
		})
	}
}

func TestCreateTransactionNilRequest(t *testing.T) {
	c, seen := recordingClient(t, http.StatusOK, `{}`)
	var typedNil *ContractCallRequest
	if _, err := c.Transaction.CreateTransaction(context.Background(), typedNil); err == nil {
		t.Error("typed nil request accepted")
	}
	if _, err := c.Transaction.CreateTransaction(context.Background(), nil); err == nil {
		t.Error("nil request accepted")
	}
	if _, err := c.Transaction.CreateTransfer(context.Background(), nil); err == nil {
		t.Error("nil transfer request accepted")
	}
	if len(*seen) != 0 {
		t.Errorf("nil requests reached the wire: %d", len(*seen))
	}
}

// ── POST /api/v1/transactions: responses ────────────────────────────────────

func TestCreateTransactionResponses(t *testing.T) {
	t.Run("200 BROADCAST with tx_hash", func(t *testing.T) {
		c, _ := recordingClient(t, http.StatusOK, `{"tx_id":"tx-b","status":"BROADCAST","message":"CONTRACT_CALL broadcast","tx_hash":"0xhash"}`)
		resp, err := c.Transaction.CreateTransaction(context.Background(), minimalContractCall())
		if err != nil {
			t.Fatal(err)
		}
		if resp.TxID != "tx-b" || resp.Status != StatusBroadcast || resp.TxHash != "0xhash" || resp.HTTPStatus != 200 || resp.Accepted() {
			t.Errorf("unexpected response: %+v", resp)
		}
	})
	t.Run("202 PENDING outcome unknown", func(t *testing.T) {
		msg := "PROGRAM_CALL accepted but the signing engine did not answer in time; poll GET /api/v1/transactions/tx-p for the outcome and do not resubmit with the same reference_id"
		c, _ := recordingClient(t, http.StatusAccepted, `{"tx_id":"tx-p","status":"PENDING","message":"`+msg+`"}`)
		resp, err := c.Transaction.CreateTransaction(context.Background(), ProgramCallRequest{FromAddress: "p", Chain: "solana", SignedTransaction: "AQ=="})
		if err != nil {
			t.Fatalf("202 must not be an error: %v", err)
		}
		if !resp.Accepted() || resp.HTTPStatus != http.StatusAccepted || resp.TxID != "tx-p" || resp.Status != StatusPending || resp.TxHash != "" || resp.Message != msg {
			t.Errorf("202 not projected: %+v", resp)
		}
	})
	t.Run("200 TRANSFER PENDING", func(t *testing.T) {
		c, _ := recordingClient(t, http.StatusOK, `{"tx_id":"tx-t","status":"PENDING","message":"Transfer task created"}`)
		resp, err := c.Transaction.CreateTransaction(context.Background(), TransferRequest{FromAddress: "a", ToAddress: "b", Chain: "ethereum", TokenSymbol: "ETH", Amount: "1"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Accepted() || resp.Status != StatusPending || resp.TxID != "tx-t" || resp.Operation != OperationTransfer {
			t.Errorf("unexpected response: %+v", resp)
		}
	})
	t.Run("Idempotency-Key replay of a 202 arrives as 200 PENDING", func(t *testing.T) {
		// middleware/idempotency.go replays the cached body with c.Data(200, …):
		// the original 202 is not preserved. Only the operation tells a
		// CONTRACT_CALL "outcome unknown" from a TRANSFER "queued".
		replay := `{"tx_id":"tx-p","status":"PENDING","message":"CONTRACT_CALL accepted but the signing engine did not answer in time; poll GET /api/v1/transactions/tx-p for the outcome and do not resubmit with the same reference_id"}`
		c, _ := recordingClient(t, http.StatusOK, replay)
		resp, err := c.Transaction.CreateTransaction(context.Background(), minimalContractCall(), WithIdempotencyKey("idem-replay"))
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Accepted() || resp.HTTPStatus != http.StatusOK || resp.Operation != OperationContractCall || resp.TxHash != "" {
			t.Errorf("replayed 202 not recognised as accepted: %+v", resp)
		}
		pc, err := c.Transaction.CreateTransaction(context.Background(), ProgramCallRequest{FromAddress: "p", Chain: "solana", SignedTransaction: "AQ=="})
		if err != nil || !pc.Accepted() || pc.Operation != OperationProgramCall {
			t.Errorf("PROGRAM_CALL 200 PENDING must be accepted: %+v %v", pc, err)
		}
		var nilResp *CreateTransactionResponse
		if nilResp.Accepted() {
			t.Error("nil response must not be accepted")
		}
	})
	t.Run("BROADCAST is never accepted", func(t *testing.T) {
		c, _ := recordingClient(t, http.StatusOK, `{"tx_id":"tx-b","status":"BROADCAST","message":"PROGRAM_CALL broadcast","tx_hash":"0xh"}`)
		resp, err := c.Transaction.CreateTransaction(context.Background(), ProgramCallRequest{FromAddress: "p", Chain: "solana", SignedTransaction: "AQ=="})
		if err != nil || resp.Accepted() || resp.Operation != OperationProgramCall {
			t.Errorf("unexpected: %+v %v", resp, err)
		}
	})
}

func minimalContractCall() ContractCallRequest {
	return ContractCallRequest{
		FromAddress: "0xpayer", Chain: "ethereum",
		ContractCall: ContractCall{
			QuoteID: "ab", Expiration: 1,
			Incoming:              ContractCallIncomingLeg{To: "0x1", Token: "0x2", Amount: "3"},
			Outgoing:              ContractCallOutgoingLeg{From: "0x1", To: "0xpayer", Token: "0x4", Amount: "5"},
			CounterpartySignature: "0x6",
		},
	}
}

// ── CreateTransfer compatibility wrapper ────────────────────────────────────

func TestCreateTransferUsesUnifiedEntry(t *testing.T) {
	c, seen := recordingClient(t, http.StatusOK, `{"tx_id":"tx-1","status":"PENDING","message":"Transfer task created"}`)
	resp, err := c.Transaction.CreateTransfer(context.Background(), &CreateTransferRequest{
		FromAddress: "0xfrom", ToAddress: "0xto", Chain: "polygon", TokenSymbol: "POL", Amount: "0.1", Memo: "m",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TxID != "tx-1" || resp.Status != StatusPending {
		t.Errorf("unexpected response: %+v", resp)
	}
	got := (*seen)[0]
	if got.Path != "/api/v1/transactions" || got.Method != http.MethodPost {
		t.Fatalf("CreateTransfer hit %s %s, want POST /api/v1/transactions", got.Method, got.Path)
	}
	want := `{"operation":"TRANSFER","from_address":"0xfrom","chain":"polygon","memo":"m","to_address":"0xto","token_symbol":"POL","amount":"0.1"}`
	if string(got.Body) != want {
		t.Errorf("body mismatch\n got: %s\nwant: %s", got.Body, want)
	}
	// Legacy aliases still resolve to the new types.
	var _ *TransferResponse = resp
	var _ TransferRequest = CreateTransferRequest{}
}

// ── Errors ──────────────────────────────────────────────────────────────────

func TestRejectedReasonTag(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		rejected bool
		tag      string
	}{
		{"verifier rejection", 400, errBody(CodeInvalidParam, TypeInvalidRequest, "Rejected: counterparty_not_registered: incoming.to 0xcf8a is not a registered counterparty"), true, ReasonCounterpartyNotRegistered},
		{"rejection without detail", 400, errBody(CodeInvalidParam, TypeInvalidRequest, "Rejected: limit_daily"), true, ReasonLimitDaily},
		{"engine failure with tag", 400, errBody(CodeTransactionFailed, TypeBusiness, "CONTRACT_CALL failed: permit_deadline_passed"), false, ReasonPermitDeadlinePassed},
		{"engine failure generic", 400, errBody(CodeTransactionFailed, TypeBusiness, "PROGRAM_CALL failed: engine rejected the transaction"), false, ""},
		{"plain invalid parameter", 400, errBody(CodeInvalidParam, TypeInvalidRequest, "Invalid request parameters: signed_transaction is required for PROGRAM_CALL"), false, ""},
		{"unsupported operation", 400, errBody(CodeInvalidParam, TypeInvalidRequest, "Unsupported operation: only TRANSFER, PROGRAM_CALL and CONTRACT_CALL are available"), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := recordingClient(t, tc.status, tc.body)
			_, err := c.Transaction.CreateTransaction(context.Background(), minimalContractCall())
			if err == nil {
				t.Fatal("expected error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("not an *APIError: %v", err)
			}
			if IsRejected(err) != tc.rejected || apiErr.IsRejected() != tc.rejected {
				t.Errorf("IsRejected = %v, want %v", IsRejected(err), tc.rejected)
			}
			if got := RejectionReason(err); got != tc.tag {
				t.Errorf("RejectionReason = %q, want %q", got, tc.tag)
			}
			if got := apiErr.ReasonTag(); got != tc.tag {
				t.Errorf("ReasonTag = %q, want %q", got, tc.tag)
			}
			if tc.name == "engine failure with tag" && !IsTransactionFailed(err) {
				t.Error("IsTransactionFailed should be true")
			}
		})
	}
	if RejectionReason(errors.New("plain")) != "" || IsRejected(nil) {
		t.Error("non-API errors must not carry a tag")
	}
}

func TestErrorClassification(t *testing.T) {
	retired := errBody(CodeInvalidParam, TypeEndpointRetired, "This endpoint has been retired. Use POST /api/v1/transactions (operation=TRANSFER).")
	cases := []struct {
		name   string
		status int
		body   string
		check  func(error) bool
		code   string
	}{
		{"403 no policy", 403, errBody(CodeForbidden, TypePermission, "policy not authorized: no OPERATION_RULES policy allows CONTRACT_CALL on ethereum"), IsForbidden, CodeForbidden},
		{"404 asset not credited", 404, errBody(CodeResourceNotFound, TypeNotFound, "no asset registered for token 0x59fb on ethereum"), IsNotFound, CodeResourceNotFound},
		{"503 engine busy", 503, errBody(CodeServiceUnavailable, TypeAPI, "Signing service is busy, retry later"), IsServiceUnavailable, CodeServiceUnavailable},
		{"503 chain rpc", 503, errBody(CodeServiceUnavailable, TypeAPI, "Chain RPC unavailable; cannot verify request"), IsServiceUnavailable, CodeServiceUnavailable},
		{"410 retired endpoint", 410, retired, IsEndpointRetired, CodeInvalidParam},
		{"400 duplicate reference", 400, errBody(CodeInvalidParam, TypeInvalidRequest, "Duplicate reference_id: this reference has already been used"), IsDuplicateReferenceID, CodeInvalidParam},
		{"400 insufficient balance", 400, errBody(CodeInsufficientBalance, TypeBusiness, "Insufficient balance"), IsInsufficientBalance, CodeInsufficientBalance},
		{"429 rate limited", 429, errBody(CodeTooManyRequests, TypeRateLimit, "slow down"), IsRateLimited, CodeTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := recordingClient(t, tc.status, tc.body)
			_, err := c.Transaction.CreateTransaction(context.Background(), minimalContractCall())
			if err == nil {
				t.Fatal("expected error")
			}
			if !tc.check(err) {
				t.Errorf("classifier returned false for %v", err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.HTTPStatus != tc.status || apiErr.Code != tc.code {
				t.Errorf("APIError not preserved: %+v", apiErr)
			}
			if tc.status == 410 && apiErr.Type != TypeEndpointRetired {
				t.Errorf("410 type = %q", apiErr.Type)
			}
			// The other classifiers must not fire.
			for name, other := range map[string]func(error) bool{
				"IsForbidden": IsForbidden, "IsNotFound": IsNotFound, "IsServiceUnavailable": IsServiceUnavailable,
				"IsEndpointRetired": IsEndpointRetired, "IsDuplicateReferenceID": IsDuplicateReferenceID,
				"IsInsufficientBalance": IsInsufficientBalance, "IsRateLimited": IsRateLimited,
			} {
				if reflect.ValueOf(other).Pointer() != reflect.ValueOf(tc.check).Pointer() && other(err) {
					t.Errorf("%s wrongly true for %s", name, tc.name)
				}
			}
			if IsRejected(err) || RejectionReason(err) != "" {
				t.Errorf("%s is not a rejection", tc.name)
			}
		})
	}
}

func TestForbiddenDistinguishesBlacklistFromPolicy(t *testing.T) {
	// transaction_handler.go createTransfer: ErrAddressBlacklisted →
	// code=address_blacklisted, mapped to HTTP 403 (common/errors.go
	// httpStatusMap). Same status as "no OPERATION_RULES policy", different code.
	c, _ := recordingClient(t, http.StatusForbidden, errBody(CodeAddressBlacklisted, TypePermission, "Destination address is blacklisted"))
	_, err := c.Transaction.CreateTransfer(context.Background(), &TransferRequest{FromAddress: "a", ToAddress: "b", Chain: "ethereum", TokenSymbol: "ETH", Amount: "1"})
	if !IsForbidden(err) || !IsAddressBlacklisted(err) || !IsAuthError(err) {
		t.Errorf("403 address_blacklisted not classified: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != CodeAddressBlacklisted || apiErr.HTTPStatus != http.StatusForbidden {
		t.Errorf("APIError not preserved: %+v", apiErr)
	}

	c2, _ := recordingClient(t, http.StatusForbidden, errBody(CodeForbidden, TypePermission, "policy not authorized: no OPERATION_RULES policy allows CONTRACT_CALL on ethereum"))
	_, err = c2.Transaction.CreateTransaction(context.Background(), minimalContractCall())
	if !IsForbidden(err) || IsAddressBlacklisted(err) {
		t.Errorf("policy 403 must not look blacklisted: %v", err)
	}
	if IsAddressBlacklisted(nil) || IsAddressBlacklisted(errors.New("x")) {
		t.Error("non-API errors must not classify")
	}
}

func TestRetiredEndpointsAreNotCalled(t *testing.T) {
	// Every path the SDK can emit is recorded; none may be a retired endpoint.
	c, seen := recordingClient(t, http.StatusOK, `{"data":[],"total":0,"has_more":false}`)
	ctx := context.Background()
	_, _ = c.Transaction.CreateTransfer(ctx, &TransferRequest{FromAddress: "a", ToAddress: "b", Chain: "ethereum", TokenSymbol: "ETH", Amount: "1"})
	_, _ = c.Transaction.CreateTransaction(ctx, minimalContractCall())
	_, _ = c.Transaction.ListTransactions(ctx, nil)
	_, _ = c.X402.X402ListSettlements(ctx, nil)
	_, _ = c.X402.X402Verify(ctx, map[string]interface{}{})
	_, _ = c.X402.X402Settle(ctx, map[string]interface{}{})
	_, _ = c.X402.X402SettleStatus(ctx, "x")
	for _, r := range *seen {
		if r.Path == "/api/v1/transfer" || r.Path == "/api/v1/x402/sign" || strings.Contains(r.Path, "external_tx_id") || strings.Contains(r.Path, "asset-changes") {
			t.Errorf("retired / non-existent endpoint called: %s %s", r.Method, r.Path)
		}
	}
}

func TestNonJSONErrorBody(t *testing.T) {
	c, _ := recordingClient(t, http.StatusBadGateway, "<html>bad gateway</html>")
	_, err := c.Transaction.GetTransaction(context.Background(), "tx")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != 502 || apiErr.Code != "unknown" || apiErr.Message != "<html>bad gateway</html>" {
		t.Errorf("non-JSON body not preserved: %v", err)
	}
}

// ── Auth: token lifetime and 401 token_expired retry ────────────────────────

func TestTokenExpiredRefreshesAndRetriesOnce(t *testing.T) {
	var calls atomic.Int32
	c, auth := contractClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			if r.Header.Get("Authorization") != "Bearer jwt-1" {
				t.Errorf("first call token = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(errBody(CodeTokenExpired, TypeAuthentication, "Token expired")))
			return
		}
		if r.Header.Get("Authorization") != "Bearer jwt-2" {
			t.Errorf("retry did not use the refreshed token: %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"operation":"TRANSFER"`) {
			t.Errorf("retry lost the request body: %s", body)
		}
		_, _ = w.Write([]byte(`{"tx_id":"tx-1","status":"PENDING","message":"Transfer task created"}`))
	})
	resp, err := c.Transaction.CreateTransfer(context.Background(), &TransferRequest{FromAddress: "a", ToAddress: "b", Chain: "ethereum", TokenSymbol: "ETH", Amount: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TxID != "tx-1" || calls.Load() != 2 || auth.Load() != 2 {
		t.Errorf("resp=%+v business calls=%d auth calls=%d", resp, calls.Load(), auth.Load())
	}
}

func TestTokenExpiredRetriesOnlyOnce(t *testing.T) {
	var calls atomic.Int32
	c, auth := contractClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(errBody(CodeTokenExpired, TypeAuthentication, "Token expired")))
	})
	_, err := c.Transaction.GetTransaction(context.Background(), "tx")
	if !IsTokenExpired(err) || !IsAuthError(err) {
		t.Fatalf("expected token_expired, got %v", err)
	}
	if calls.Load() != 2 || auth.Load() != 2 {
		t.Errorf("business calls=%d auth calls=%d, want 2/2", calls.Load(), auth.Load())
	}
}

func TestOtherUnauthorizedIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	c, auth := contractClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(errBody(CodeInvalidToken, TypeAuthentication, "Invalid token")))
	})
	_, err := c.Transaction.GetTransaction(context.Background(), "tx")
	if !IsAuthError(err) || IsTokenExpired(err) {
		t.Fatalf("unexpected classification: %v", err)
	}
	if calls.Load() != 1 || auth.Load() != 1 {
		t.Errorf("business calls=%d auth calls=%d, want 1/1", calls.Load(), auth.Load())
	}
}

func TestTokenCachedUntilExpiresIn(t *testing.T) {
	c, auth := contractClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[],"total":0,"has_more":false}`))
	})
	before := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.Transaction.ListTransactions(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if auth.Load() != 1 {
		t.Errorf("token fetched %d times for 3 calls", auth.Load())
	}
	// expires_in=900 → refresh 120s early.
	want := before.Add(780 * time.Second)
	if got := c.tokenManager.expiresAt; got.Before(want.Add(-5*time.Second)) || got.After(want.Add(5*time.Second)) {
		t.Errorf("expiresAt = %v, want ≈ %v", got, want)
	}
}

func TestAuthFailureIsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(errBody(CodeForbidden, TypePermission, "IP not allowed: 203.0.113.9")))
	}))
	defer srv.Close()
	c, _ := NewMPCClient("k", "s", Custom(srv.URL))
	_, err := c.Wallet.ListWallets(context.Background(), nil)
	if !IsForbidden(err) {
		t.Errorf("auth 403 not surfaced as APIError: %v", err)
	}
}

// ── Idempotency-Key ─────────────────────────────────────────────────────────

func TestIdempotencyKeyHeader(t *testing.T) {
	c, seen := recordingClient(t, http.StatusOK, `{"tx_id":"tx-1","status":"PENDING","message":"ok","success":true,"transaction":"0x"}`)
	ctx := context.Background()
	if _, err := c.Transaction.CreateTransaction(ctx, minimalContractCall(), WithIdempotencyKey("idem-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.X402.X402Settle(ctx, map[string]interface{}{"x402Version": 2}, WithIdempotencyKey("idem-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Transaction.CreateTransaction(ctx, minimalContractCall()); err != nil {
		t.Fatal(err)
	}
	if h := (*seen)[0].Headers.Get("Idempotency-Key"); h != "idem-1" {
		t.Errorf("transactions Idempotency-Key = %q", h)
	}
	if h := (*seen)[1].Headers.Get("Idempotency-Key"); h != "idem-2" || (*seen)[1].Path != "/api/v1/x402/settle" {
		t.Errorf("settle Idempotency-Key = %q path=%s", h, (*seen)[1].Path)
	}
	if _, ok := (*seen)[2].Headers["Idempotency-Key"]; ok {
		t.Error("Idempotency-Key sent without being asked")
	}
}

// ── GET endpoints ───────────────────────────────────────────────────────────

func TestGetTransactionAndList(t *testing.T) {
	c, seen := recordingClient(t, http.StatusOK, `{"tx_id":"a/b","wallet_id":"w","client_id":"c","chain":"ethereum","transaction_type":"OUTBOUND","from_address":"f","to_address":"t","token_symbol":"USDT","amount":"1.5","status":"CONFIRMED","tx_hash":"0xh","risk_score":"0.1","risk_level":"LOW","created_at":"2026-09-15T00:00:00Z","data":[],"total":0,"has_more":false}`)
	ctx := context.Background()
	tx, err := c.Transaction.GetTransaction(ctx, "a/b")
	if err != nil {
		t.Fatal(err)
	}
	if tx.TxID != "a/b" || tx.RiskLevel != "LOW" || tx.RiskScore != "0.1" || tx.TxHash != "0xh" || tx.TransactionType != "OUTBOUND" {
		t.Errorf("transaction not decoded: %+v", tx)
	}
	if got := (*seen)[0].RawPath; got != "/api/v1/transactions/a%2Fb" {
		t.Errorf("tx id not escaped: %s", got)
	}
	if _, err := c.Transaction.GetTransaction(ctx, ""); err == nil {
		t.Error("empty tx id accepted")
	}
	if _, err := c.Transaction.ListTransactions(ctx, &ListTransactionsRequest{WalletID: "w1", AccountID: "a1", Chain: "solana", Page: 2, PageSize: 50}); err != nil {
		t.Fatal(err)
	}
	list := (*seen)[1]
	if list.Method != http.MethodGet || list.Path != "/api/v1/transactions" || list.Query != "account_id=a1&chain=solana&page=2&page_size=50&wallet_id=w1" {
		t.Errorf("list route: %s %s?%s", list.Method, list.Path, list.Query)
	}
	if list.Headers.Get("Content-Type") != "" {
		t.Error("GET must not send Content-Type")
	}
}

// ── x402 facilitator ────────────────────────────────────────────────────────

func TestX402FacilitatorPaths(t *testing.T) {
	c, seen := recordingClient(t, http.StatusOK, `{"isValid":true,"payer":"0xp","success":true,"txId":"tx-9","transaction":"0xt","network":"base-sepolia","status":"SETTLED","txHash":"0xt","data":[{"tx_id":"s1","chain":"base","from_address":"f","to_address":"t","amount":"1","status":"SETTLED","valid_before":1800000000,"created_at":"2026-01-01T00:00:00Z"}],"total":1,"has_more":false}`)
	ctx := context.Background()

	v, err := c.X402.X402Verify(ctx, map[string]interface{}{"x402Version": 2})
	if err != nil || !v.IsValid || v.Payer != "0xp" {
		t.Errorf("verify: %+v %v", v, err)
	}
	s, err := c.X402.X402Settle(ctx, map[string]interface{}{"x402Version": 2})
	if err != nil || !s.Success || s.TxID != "tx-9" || s.Transaction != "0xt" || s.Network != "base-sepolia" {
		t.Errorf("settle: %+v %v", s, err)
	}
	st, err := c.X402.X402SettleStatus(ctx, "tx-9")
	if err != nil || st.TxID != "tx-9" || st.Status != "SETTLED" || st.TxHash != "0xt" || !st.Success {
		t.Errorf("settle status: %+v %v", st, err)
	}
	l, err := c.X402.X402ListSettlements(ctx, &ListX402SettlementsRequest{Status: "SETTLED", Page: 1, PageSize: 20})
	if err != nil || len(l.Items) != 1 || l.Items[0].TxID != "s1" || l.Items[0].ValidBefore != 1800000000 {
		t.Errorf("settlements: %+v %v", l, err)
	}

	want := []string{
		"POST /api/v1/x402/verify?",
		"POST /api/v1/x402/settle?",
		"GET /api/v1/x402/settle/tx-9?",
		"GET /api/v1/x402/settlements?page=1&page_size=20&status=SETTLED",
	}
	for i, w := range want {
		got := (*seen)[i].Method + " " + (*seen)[i].Path + "?" + (*seen)[i].Query
		if got != w {
			t.Errorf("call %d = %q, want %q", i, got, w)
		}
	}
}

func TestX402SignRemoved(t *testing.T) {
	svc := reflect.TypeOf(&service{})
	for i := 0; i < svc.NumMethod(); i++ {
		name := svc.Method(i).Name
		if strings.Contains(name, "X402Sign") || strings.Contains(name, "ExternalTxID") || strings.Contains(name, "AssetChange") {
			t.Errorf("method %s must not exist: the endpoint is retired or never shipped", name)
		}
	}
	if _, ok := svc.MethodByName("X402Sign"); ok {
		t.Error("X402Sign still exists")
	}
}

// ── Redirects are never followed ────────────────────────────────────────────

func TestRedirectNotFollowed(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		for _, phase := range []string{"auth", "api"} {
			t.Run(fmt.Sprintf("%s/%d", phase, status), func(t *testing.T) {
				var forwarded atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forwarded.Add(1)
					_, _ = w.Write([]byte(`{"token":"leaked","expires_in":900}`))
				}))
				defer target.Close()
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", target.URL+"/elsewhere?secret=fixture-do-not-log")
					w.WriteHeader(status)
				}))
				defer origin.Close()
				c, _ := NewMPCClient("k", "s", Custom(origin.URL))
				var err error
				if phase == "auth" {
					_, err = c.tokenManager.getToken(context.Background())
				} else {
					c.tokenManager.token = "t"
					c.tokenManager.expiresAt = time.Now().Add(time.Hour)
					_, err = c.Transaction.GetTransaction(context.Background(), "x")
				}
				if forwarded.Load() != 0 {
					t.Errorf("redirect followed %d times", forwarded.Load())
				}
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.HTTPStatus != status {
					t.Errorf("expected APIError with status %d, got %v", status, err)
				}
				if strings.Contains(fmt.Sprint(err), "fixture-do-not-log") {
					t.Error("redirect target leaked into the error")
				}
			})
		}
	}
}

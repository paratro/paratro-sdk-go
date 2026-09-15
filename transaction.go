package paratro

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
)

// Operation selects the branch of the unified entry POST /api/v1/transactions.
type Operation = string

// Operations accepted by POST /api/v1/transactions. Anything else (including
// X402) is answered with 400 "Unsupported operation".
const (
	// OperationTransfer sends funds to an address. Asynchronous: the gateway
	// answers 200 status=PENDING and signs in the background.
	OperationTransfer Operation = "TRANSFER"
	// OperationProgramCall co-signs a counterparty-built Solana transaction
	// (xChange fixed-shape swap). Synchronous: 200 status=BROADCAST + tx_hash.
	OperationProgramCall Operation = "PROGRAM_CALL"
	// OperationContractCall signs an xChange executeSwap on an EVM chain.
	// Synchronous: 200 status=BROADCAST + tx_hash.
	OperationContractCall Operation = "CONTRACT_CALL"
)

// Status values returned by CreateTransaction.
const (
	// StatusPending: TRANSFER accepted for asynchronous signing (HTTP 200), or
	// PROGRAM_CALL / CONTRACT_CALL whose engine outcome is unknown (HTTP 202).
	StatusPending = "PENDING"
	// StatusBroadcast: PROGRAM_CALL / CONTRACT_CALL signed and broadcast; TxHash is set.
	StatusBroadcast = "BROADCAST"
)

// TransactionRequest is the request of CreateTransaction. It is implemented by
// TransferRequest, ProgramCallRequest and ContractCallRequest (values or
// pointers); each marshals to the wire body of its operation.
type TransactionRequest interface {
	// Operation returns the operation the request is built for.
	Operation() Operation
	json.Marshaler
}

// createTransactionBody is the wire shape of POST /api/v1/transactions
// (gateway dto.CreateTransactionRequest). Field order is the JSON order.
type createTransactionBody struct {
	Operation         Operation     `json:"operation"`
	ReferenceID       string        `json:"reference_id,omitempty"`
	FromAddress       string        `json:"from_address"`
	Chain             string        `json:"chain"`
	Memo              string        `json:"memo,omitempty"`
	ToAddress         string        `json:"to_address,omitempty"`
	TokenSymbol       string        `json:"token_symbol,omitempty"`
	Amount            string        `json:"amount,omitempty"`
	ReceiveAddress    string        `json:"receive_address,omitempty"`
	SignedTransaction string        `json:"signed_transaction,omitempty"`
	ContractCall      *ContractCall `json:"contract_call,omitempty"`
}

// TransferRequest is operation=TRANSFER: send funds from one of your accounts
// to an address. Amount is a human-readable decimal string ("10.5"), at most
// 18 decimal places.
type TransferRequest struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Chain       string `json:"chain"`
	TokenSymbol string `json:"token_symbol"`
	Amount      string `json:"amount"`
	// Memo is optional, at most 100 characters.
	Memo string `json:"memo,omitempty"`
	// ReferenceID is your business reference (order / invoice number), at most
	// 100 characters. Reusing one within the same client → 400 Duplicate reference_id.
	ReferenceID string `json:"reference_id,omitempty"`
}

// Operation implements TransactionRequest.
func (TransferRequest) Operation() Operation { return OperationTransfer }

// MarshalJSON implements json.Marshaler with the unified-entry body.
func (r TransferRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(createTransactionBody{
		Operation:   OperationTransfer,
		ReferenceID: r.ReferenceID,
		FromAddress: r.FromAddress,
		Chain:       r.Chain,
		Memo:        r.Memo,
		ToAddress:   r.ToAddress,
		TokenSymbol: r.TokenSymbol,
		Amount:      r.Amount,
	})
}

// ProgramCallRequest is operation=PROGRAM_CALL (chain "solana" only): the
// gateway verifies and co-signs a counterparty-built, partially signed Solana
// transaction and broadcasts it.
type ProgramCallRequest struct {
	// FromAddress is your paying wallet. It must sit in the fee-payer slot
	// (AccountKeys[0]) of the transaction with an empty signature slot.
	FromAddress string `json:"from_address"`
	// Chain must be "solana".
	Chain string `json:"chain"`
	// SignedTransaction is the counterparty-signed transaction, base64 or
	// 0x-hex encoded (≤ 4096 characters).
	SignedTransaction string `json:"signed_transaction"`
	// ReceiveAddress is your receiving wallet; defaults to FromAddress. Both
	// must be accounts of this client.
	ReceiveAddress string `json:"receive_address,omitempty"`
	ReferenceID    string `json:"reference_id,omitempty"`
	Memo           string `json:"memo,omitempty"`
}

// Operation implements TransactionRequest.
func (ProgramCallRequest) Operation() Operation { return OperationProgramCall }

// MarshalJSON implements json.Marshaler with the unified-entry body.
func (r ProgramCallRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(createTransactionBody{
		Operation:         OperationProgramCall,
		ReferenceID:       r.ReferenceID,
		FromAddress:       r.FromAddress,
		Chain:             r.Chain,
		Memo:              r.Memo,
		ReceiveAddress:    r.ReceiveAddress,
		SignedTransaction: r.SignedTransaction,
	})
}

// ContractCallRequest is operation=CONTRACT_CALL (EVM chains): the gateway
// signs an EIP-2612 permit plus the xChange executeSwap call for the quote in
// ContractCall and broadcasts it. The contract address comes from the client's
// OPERATION_RULES policy (call_rules.allowed_contracts[chain]) — it is never
// part of the request — and the native value is always 0.
type ContractCallRequest struct {
	// FromAddress is your paying wallet: incoming.from, the permit owner and
	// the transaction sender. The quote must have been generated for it.
	FromAddress string `json:"from_address"`
	Chain       string `json:"chain"`
	// ReceiveAddress is your receiving wallet (= outgoing.to); defaults to FromAddress.
	ReceiveAddress string       `json:"receive_address,omitempty"`
	ContractCall   ContractCall `json:"contract_call"`
	ReferenceID    string       `json:"reference_id,omitempty"`
	Memo           string       `json:"memo,omitempty"`
}

// Operation implements TransactionRequest.
func (ContractCallRequest) Operation() Operation { return OperationContractCall }

// MarshalJSON implements json.Marshaler with the unified-entry body.
func (r ContractCallRequest) MarshalJSON() ([]byte, error) {
	cc := r.ContractCall
	return json.Marshal(createTransactionBody{
		Operation:      OperationContractCall,
		ReferenceID:    r.ReferenceID,
		FromAddress:    r.FromAddress,
		Chain:          r.Chain,
		Memo:           r.Memo,
		ReceiveAddress: r.ReceiveAddress,
		ContractCall:   &cc,
	})
}

// ContractCall is the executeSwap quote handed over verbatim. All amounts are
// smallest-unit decimal integer strings (no decimals, sign or 0x).
type ContractCall struct {
	// QuoteID is the bytes32 quote id as hex (0x prefix optional).
	QuoteID string `json:"quote_id"`
	// Expiration is a unix timestamp in seconds; must be in the future and at
	// most now + fee_limits.max_execution_timeout_seconds of the policy.
	Expiration int64 `json:"expiration"`
	// Incoming is the leg you pay to the counterparty.
	Incoming ContractCallIncomingLeg `json:"incoming"`
	// Outgoing is the leg the counterparty pays to you.
	Outgoing ContractCallOutgoingLeg `json:"outgoing"`
	// CounterpartySignature is the counterparty's EIP-712 signature over the
	// quote (hex). The gateway does not verify it; the contract does.
	CounterpartySignature string `json:"counterparty_signature"`
	// PermitDeadline is optional (unix seconds); 0 lets the gateway pick
	// now + min(fee_limits.max_permit_lifetime_seconds, 300).
	PermitDeadline int64 `json:"permit_deadline,omitempty"`
}

// ContractCallIncomingLeg is the leg you pay: To must be a policy counterparty,
// Token a policy payment token, Amount within single_limit / daily_limit.
type ContractCallIncomingLeg struct {
	To     string `json:"to"`
	Token  string `json:"token"`
	Amount string `json:"amount"`
}

// ContractCallOutgoingLeg is the leg the counterparty pays you: From must be a
// policy counterparty, To your receiving wallet, Token a policy target token.
type ContractCallOutgoingLeg struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Token  string `json:"token"`
	Amount string `json:"amount"`
}

// CreateTransactionResponse is the body of POST /api/v1/transactions
// (gateway dto.TransferResponse) plus the HTTP status it came with.
type CreateTransactionResponse struct {
	TxID    string `json:"tx_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	// TxHash is set only for synchronously broadcast operations
	// (PROGRAM_CALL / CONTRACT_CALL with status BROADCAST).
	TxHash string `json:"tx_hash,omitempty"`
	// HTTPStatus is 200 or 202 (see Accepted).
	HTTPStatus int `json:"-"`
	// Operation is the operation of the request this response answers; the
	// gateway does not echo it, the SDK fills it in.
	Operation Operation `json:"-"`
}

// Accepted reports whether the outcome of a PROGRAM_CALL / CONTRACT_CALL is
// unknown: the transaction row was created but the signing engine did not
// answer in time. It may still be signing or may already be broadcast. Poll
// GetTransaction(TxID) until the status settles. Do NOT resubmit with the same
// reference_id (it would be rejected as a duplicate) and do not resubmit with a
// new one either, or you may pay twice.
//
// The gateway signals this with HTTP 202. An Idempotency-Key replay of such an
// answer comes back as HTTP 200 with the same body (status PENDING and no
// tx_hash), so Accepted also treats "PROGRAM_CALL / CONTRACT_CALL with status
// PENDING" as accepted: those operations never answer PENDING otherwise. A
// TRANSFER's normal 200 PENDING is not "accepted" in this sense.
func (r *CreateTransactionResponse) Accepted() bool {
	if r == nil {
		return false
	}
	if r.HTTPStatus == http.StatusAccepted {
		return true
	}
	return r.Operation != "" && r.Operation != OperationTransfer && r.Status == StatusPending
}

// CreateTransaction calls POST /api/v1/transactions with a TransferRequest,
// ProgramCallRequest or ContractCallRequest.
//
// Responses:
//
//	200 {tx_id,status:"PENDING"}            TRANSFER queued for asynchronous signing
//	200 {tx_id,status:"BROADCAST",tx_hash}  PROGRAM_CALL / CONTRACT_CALL broadcast
//	202 {tx_id,status:"PENDING"}            PROGRAM_CALL / CONTRACT_CALL outcome unknown → Accepted(), poll by tx_id
//
// Errors are *APIError: 400 "Rejected: <tag>: …" (RejectionReason), 400
// Duplicate reference_id (IsDuplicateReferenceID), 400 insufficient_balance /
// transaction_failed, 403 no policy (IsForbidden) or blacklisted destination
// (IsAddressBlacklisted), 404 address/asset not yours or token not credited
// (IsNotFound), 503 engine busy or chain RPC unavailable (IsServiceUnavailable).
//
// # Retry guidance
//
// A 4xx/5xx means the request did not reach the chain, but it does not mean
// nothing was stored. For PROGRAM_CALL / CONTRACT_CALL the gateway creates the
// transaction row before it talks to the signing engine, and some failures
// are raised after that point: "engine busy" (503), the engine's own verdict
// (400 transaction_failed) and the CONTRACT_CALL post-sign check (400
// Rejected). The row is then FAILED (or held PENDING until the permit deadline
// when a permit was already signed) and it keeps the reference_id, whose
// uniqueness ignores status. So:
//
//   - 400 Rejected / transaction_failed / insufficient_balance, 503: retry, if
//     you retry at all, with a NEW reference_id. The same one may answer 400
//     Duplicate reference_id. When a CONTRACT_CALL fails after its permit was
//     signed (503 engine busy at broadcast, 400 Rejected from the post-sign
//     check) the previous reservation stays locked until the permit deadline,
//     so a retry can see insufficient_balance until then.
//   - 202 (Accepted): never resubmit; poll GetTransaction(TxID).
//   - Transport failure (timeout, connection reset) with no response: the
//     outcome is as unknown as a 202 but you have no tx_id. Do not resubmit
//     with a new reference_id. Provided you set a reference_id, replaying the
//     identical request (same reference_id and, if you sent one, the same
//     Idempotency-Key) is safe: with an Idempotency-Key it returns the
//     original body when the original completed with 2xx (the gateway caches
//     2xx bodies for 24h under that key); otherwise, or before the cache is
//     written, it answers 400 Duplicate reference_id when the row exists; and
//     it is a normal answer when no row was ever created — the reference_id
//     unique key guarantees at most one transaction per reference. GET
//     /api/v1/transactions cannot filter by reference_id, so always set
//     reference_id, send and keep an Idempotency-Key, and set Config.Timeout /
//     the context deadline no lower than DefaultTimeout for these two
//     operations.
func (s *service) CreateTransaction(ctx context.Context, req TransactionRequest, opts ...RequestOption) (*CreateTransactionResponse, error) {
	if isNilRequest(req) {
		return nil, fmt.Errorf("failed to create transaction: request is nil")
	}
	var response CreateTransactionResponse
	status, err := s.client.do(ctx, http.MethodPost, "/api/v1/transactions", nil, req, &response, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s transaction: %w", req.Operation(), err)
	}
	response.HTTPStatus = status
	response.Operation = req.Operation()
	return &response, nil
}

func isNilRequest(req TransactionRequest) bool {
	if req == nil {
		return true
	}
	rv := reflect.ValueOf(req)
	return rv.Kind() == reflect.Ptr && rv.IsNil()
}

// Transaction is GET /api/v1/transactions/{id} (gateway dto.TransactionResponse).
type Transaction struct {
	TxID            string `json:"tx_id"`
	WalletID        string `json:"wallet_id"`
	ClientID        string `json:"client_id"`
	Chain           string `json:"chain"`
	TransactionType string `json:"transaction_type"` // OUTBOUND, INBOUND, X402_SETTLE, GAS_REFUEL, SWEEP
	FromAddress     string `json:"from_address"`
	ToAddress       string `json:"to_address"`
	TokenSymbol     string `json:"token_symbol"`
	Amount          string `json:"amount"`
	Status          string `json:"status"`
	TxHash          string `json:"tx_hash"`
	RiskScore       string `json:"risk_score,omitempty"`
	RiskLevel       string `json:"risk_level,omitempty"`
	CreatedAt       string `json:"created_at"`
}

// GetTransaction retrieves a transaction by ID (GET /api/v1/transactions/{id}).
func (s *service) GetTransaction(ctx context.Context, txID string) (*Transaction, error) {
	if txID == "" {
		return nil, fmt.Errorf("failed to get transaction: txID is required")
	}
	var transaction Transaction
	path := "/api/v1/transactions/" + url.PathEscape(txID)
	err := s.client.request(ctx, http.MethodGet, path, nil, &transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	return &transaction, nil
}

// ListTransactionsRequest are the query parameters of GET /api/v1/transactions
// (gateway dto.TransactionRequest).
type ListTransactionsRequest struct {
	WalletID  string `json:"wallet_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Chain     string `json:"chain,omitempty"`
	Page      int    `json:"page,omitempty"`      // default 1
	PageSize  int    `json:"page_size,omitempty"` // default 20, max 100
}

// ListTransactionsResponse represents a paginated list of transactions
type ListTransactionsResponse struct {
	Items   []*Transaction `json:"data"`
	Total   int64          `json:"total"`
	HasMore bool           `json:"has_more"`
}

// ListTransactions retrieves a list of transactions
func (s *service) ListTransactions(ctx context.Context, req *ListTransactionsRequest) (*ListTransactionsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.WalletID != "" {
			params["wallet_id"] = req.WalletID
		}
		if req.AccountID != "" {
			params["account_id"] = req.AccountID
		}
		if req.Chain != "" {
			params["chain"] = req.Chain
		}
		if req.Page > 0 {
			params["page"] = strconv.Itoa(req.Page)
		}
		if req.PageSize > 0 {
			params["page_size"] = strconv.Itoa(req.PageSize)
		}
	}

	var response ListTransactionsResponse
	err := s.client.requestWithQuery(ctx, "/api/v1/transactions", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list transactions: %w", err)
	}
	return &response, nil
}

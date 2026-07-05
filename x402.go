package paratro

import (
	"context"
	"fmt"
	"strconv"
)

// X402SignRequest represents a request to create an ERC-3009 authorization signature.
type X402SignRequest struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Chain       string `json:"chain"`
	Amount      string `json:"amount"`
	ValidAfter  int64  `json:"valid_after,omitempty"`
	ValidBefore int64  `json:"valid_before"`
}

// X402SignResponse represents the x402 sign result.
// TxID is the settlement record identifier — the gateway stores this in
// pto_x402_settlements and surfaces it under json:"tx_id" for backward compat.
type X402SignResponse struct {
	TxID       string  `json:"tx_id"`
	Status     string  `json:"status"`
	Nonce      string  `json:"nonce"`
	EIP712Hash string  `json:"eip712_hash"`
	SignatureV *int32  `json:"signature_v,omitempty"`
	SignatureR *string `json:"signature_r,omitempty"`
	SignatureS *string `json:"signature_s,omitempty"`
	Error      *string `json:"error,omitempty"`
}

// X402VerifyResponse represents the result of verifying an x402 payment signature.
type X402VerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason,omitempty"`
	Payer         string `json:"payer,omitempty"`
}

// X402SettleResponse represents the result of an on-chain settlement execution.
type X402SettleResponse struct {
	Success     bool   `json:"success"`
	Transaction string `json:"transaction,omitempty"`
	Network     string `json:"network,omitempty"`
	Payer       string `json:"payer,omitempty"`
	TxID        string `json:"txId,omitempty"`
	Error       string `json:"error,omitempty"`
}

// X402SettleStatusResponse represents the status of a settle transaction.
type X402SettleStatusResponse struct {
	TxID    string `json:"tx_id"`
	Status  string `json:"status"`
	TxHash  string `json:"tx_hash,omitempty"`
	Network string `json:"network,omitempty"`
}

// X402Settlement represents an x402 authorization record.
type X402Settlement struct {
	SettlementID string  `json:"settlement_id"`
	Status       string  `json:"status"`
	FromAddress  string  `json:"from_address"`
	ToAddress    string  `json:"to_address"`
	Chain        string  `json:"chain"`
	Amount       string  `json:"amount"`
	Nonce        string  `json:"x402_nonce"`
	SignatureV   *int32  `json:"signature_v,omitempty"`
	SignatureR   *string `json:"signature_r,omitempty"`
	SignatureS   *string `json:"signature_s,omitempty"`
	CreatedAt    string  `json:"created_at"`
}

// ListX402SettlementsResponse represents a paginated list of x402 authorizations.
type ListX402SettlementsResponse struct {
	Items   []*X402Settlement `json:"data"`
	Total   int64             `json:"total"`
	HasMore bool              `json:"has_more"`
}

// X402Sign creates an ERC-3009 authorization signature.
func (s *service) X402Sign(ctx context.Context, req *X402SignRequest) (*X402SignResponse, error) {
	var response X402SignResponse
	err := s.client.request(ctx, "POST", "/api/v1/x402/sign", req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to create x402 signature: %w", err)
	}
	return &response, nil
}

// X402ListSettlements retrieves a paginated list of x402 authorization records.
func (s *service) X402ListSettlements(ctx context.Context, page, pageSize int) (*ListX402SettlementsResponse, error) {
	params := make(map[string]string)

	if page > 0 {
		params["page"] = strconv.Itoa(page)
	}
	if pageSize > 0 {
		params["page_size"] = strconv.Itoa(pageSize)
	}

	var response ListX402SettlementsResponse
	err := s.client.requestWithQuery(ctx, "/api/v1/x402/settlements", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list x402 authorizations: %w", err)
	}
	return &response, nil
}

// X402Verify verifies a payment signature. The payload varies by x402 version,
// so it accepts a generic map.
func (s *service) X402Verify(ctx context.Context, payload map[string]interface{}) (*X402VerifyResponse, error) {
	var response X402VerifyResponse
	err := s.client.request(ctx, "POST", "/api/v1/x402/verify", payload, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to verify x402 payment: %w", err)
	}
	return &response, nil
}

// X402Settle executes an on-chain settlement. The payload varies by x402 version,
// so it accepts a generic map.
func (s *service) X402Settle(ctx context.Context, payload map[string]interface{}) (*X402SettleResponse, error) {
	var response X402SettleResponse
	err := s.client.request(ctx, "POST", "/api/v1/x402/settle", payload, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to settle x402 payment: %w", err)
	}
	return &response, nil
}

// X402SettleStatus retrieves the status of a settle transaction by transaction ID.
func (s *service) X402SettleStatus(ctx context.Context, txID string) (*X402SettleStatusResponse, error) {
	var response X402SettleStatusResponse
	path := fmt.Sprintf("/api/v1/x402/settle/%s", txID)
	err := s.client.request(ctx, "GET", path, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get x402 settle status: %w", err)
	}
	return &response, nil
}

package paratro

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// x402 facilitator endpoints (verify / settle / settle status) and the payer's
// settlement list. The payer-side signing endpoint POST /api/v1/x402/sign was
// retired (HTTP 410) and has no replacement in this SDK — the unified entry
// POST /api/v1/transactions does not accept operation=X402.

// X402VerifyResponse is the body of POST /api/v1/x402/verify
// (gateway dto.X402VerifyResponse, Coinbase-compatible).
type X402VerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason,omitempty"`
	Payer         string `json:"payer,omitempty"`
}

// X402SettleResponse is the body of POST /api/v1/x402/settle
// (gateway dto.X402SettleResponse, Coinbase-compatible).
type X402SettleResponse struct {
	Success     bool   `json:"success"`
	TxID        string `json:"txId,omitempty"`
	Transaction string `json:"transaction"`
	ErrorReason string `json:"errorReason,omitempty"`
	Payer       string `json:"payer,omitempty"`
	Network     string `json:"network,omitempty"`
}

// X402SettleStatusResponse is the body of GET /api/v1/x402/settle/{tx_id}
// (gateway dto.X402SettleStatusResponse).
type X402SettleStatusResponse struct {
	Success bool   `json:"success"`
	TxID    string `json:"txId"`
	Status  string `json:"status"`
	TxHash  string `json:"txHash,omitempty"`
	Network string `json:"network"`
}

// X402Settlement is one item of GET /api/v1/x402/settlements
// (gateway dto.X402SettlementResponse).
type X402Settlement struct {
	TxID        string  `json:"tx_id"`
	Chain       string  `json:"chain"`
	FromAddress string  `json:"from_address"`
	ToAddress   string  `json:"to_address"`
	Amount      string  `json:"amount"`
	Status      string  `json:"status"`
	ValidBefore int64   `json:"valid_before"`
	SignatureV  *int32  `json:"signature_v,omitempty"`
	SignatureR  *string `json:"signature_r,omitempty"`
	SignatureS  *string `json:"signature_s,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// ListX402SettlementsRequest are the query parameters of GET /api/v1/x402/settlements
// (gateway dto.X402SettlementListRequest).
type ListX402SettlementsRequest struct {
	// Status filters by settlement status: PENDING, PROCESSING, X402_SIGNED,
	// SETTLED, CANCELLED, FAILED or EXPIRED.
	Status   string `json:"status,omitempty"`
	Page     int    `json:"page,omitempty"`      // default 1
	PageSize int    `json:"page_size,omitempty"` // default 20, max 100
}

// ListX402SettlementsResponse represents a paginated list of x402 settlements.
type ListX402SettlementsResponse struct {
	Items   []*X402Settlement `json:"data"`
	Total   int64             `json:"total"`
	HasMore bool              `json:"has_more"`
}

// X402ListSettlements retrieves a paginated list of x402 settlement records
// (GET /api/v1/x402/settlements).
func (s *service) X402ListSettlements(ctx context.Context, req *ListX402SettlementsRequest) (*ListX402SettlementsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.Status != "" {
			params["status"] = req.Status
		}
		if req.Page > 0 {
			params["page"] = strconv.Itoa(req.Page)
		}
		if req.PageSize > 0 {
			params["page_size"] = strconv.Itoa(req.PageSize)
		}
	}

	var response ListX402SettlementsResponse
	err := s.client.requestWithQuery(ctx, "/api/v1/x402/settlements", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list x402 settlements: %w", err)
	}
	return &response, nil
}

// X402Verify verifies a payment signature (POST /api/v1/x402/verify). The
// payload is the Coinbase-compatible facilitator request
// {"x402Version":1|2,"paymentPayload":…,"paymentRequirements":…(v1 only)};
// it varies by x402 version, so it accepts a generic map.
func (s *service) X402Verify(ctx context.Context, payload map[string]interface{}) (*X402VerifyResponse, error) {
	var response X402VerifyResponse
	err := s.client.request(ctx, http.MethodPost, "/api/v1/x402/verify", payload, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to verify x402 payment: %w", err)
	}
	return &response, nil
}

// X402Settle executes an on-chain settlement (POST /api/v1/x402/settle). The
// payload has the same shape as X402Verify. The endpoint honours
// WithIdempotencyKey.
func (s *service) X402Settle(ctx context.Context, payload map[string]interface{}, opts ...RequestOption) (*X402SettleResponse, error) {
	var response X402SettleResponse
	err := s.client.request(ctx, http.MethodPost, "/api/v1/x402/settle", payload, &response, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to settle x402 payment: %w", err)
	}
	return &response, nil
}

// X402SettleStatus retrieves the status of a settle transaction
// (GET /api/v1/x402/settle/{tx_id}).
func (s *service) X402SettleStatus(ctx context.Context, txID string) (*X402SettleStatusResponse, error) {
	if txID == "" {
		return nil, fmt.Errorf("failed to get x402 settle status: txID is required")
	}
	var response X402SettleStatusResponse
	path := "/api/v1/x402/settle/" + url.PathEscape(txID)
	err := s.client.request(ctx, http.MethodGet, path, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get x402 settle status: %w", err)
	}
	return &response, nil
}

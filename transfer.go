package paratro

import (
	"context"
	"fmt"
)

// CreateTransferRequest is the pre-1.8 name of TransferRequest, kept so existing
// callers compile. New code should use TransferRequest.
type CreateTransferRequest = TransferRequest

// TransferResponse is the pre-1.8 name of CreateTransactionResponse.
type TransferResponse = CreateTransactionResponse

// CreateTransfer is a compatibility wrapper kept from 1.7. POST /api/v1/transfer
// was retired (HTTP 410); this method now sends
// POST /api/v1/transactions with operation=TRANSFER — the same request fields
// plus the optional ReferenceID — and is equivalent to
// CreateTransaction(ctx, req). The gateway answers 200 status=PENDING; signing
// happens asynchronously, follow up with GetTransaction or webhooks.
func (s *service) CreateTransfer(ctx context.Context, req *TransferRequest, opts ...RequestOption) (*TransferResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("failed to create transfer: request is nil")
	}
	return s.CreateTransaction(ctx, req, opts...)
}

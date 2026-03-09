package paratro

import (
	"context"
	"fmt"
)

// CreateTransferRequest represents a request to create a transfer
type CreateTransferRequest struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Chain       string `json:"chain"`
	TokenSymbol string `json:"token_symbol"`
	Amount      string `json:"amount"`
	Memo        string `json:"memo,omitempty"`
}

// TransferResponse represents the response of a transfer creation
type TransferResponse struct {
	TxID    string `json:"tx_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// CreateTransfer creates a transfer task to send funds to an external address
func (s *service) CreateTransfer(ctx context.Context, req *CreateTransferRequest) (*TransferResponse, error) {
	var response TransferResponse
	err := s.client.request(ctx, "POST", "/api/v1/transfer", req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to create transfer: %w", err)
	}
	return &response, nil
}

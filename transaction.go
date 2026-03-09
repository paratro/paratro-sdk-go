package paratro

import (
	"context"
	"fmt"
	"strconv"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	TxID            string `json:"tx_id"`
	WalletID        string `json:"wallet_id"`
	ClientID        string `json:"client_id"`
	Chain           string `json:"chain"`
	TransactionType string `json:"transaction_type"` // DEPOSIT, TRANSFER, etc.
	FromAddress     string `json:"from_address"`
	ToAddress       string `json:"to_address"`
	TokenSymbol     string `json:"token_symbol"`
	Amount          string `json:"amount"`
	Status          string `json:"status"` // PENDING, SUCCESS, FAILED, etc.
	TxHash          string `json:"tx_hash"`
	CreatedAt       string `json:"created_at"`
}

// GetTransaction retrieves a transaction by ID
func (s *service) GetTransaction(ctx context.Context, txID string) (*Transaction, error) {
	var transaction Transaction
	path := fmt.Sprintf("/api/v1/transactions/%s", txID)
	err := s.client.request(ctx, "GET", path, nil, &transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	return &transaction, nil
}

// ListTransactionsRequest represents a request to list transactions
type ListTransactionsRequest struct {
	WalletID  string `json:"wallet_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Chain     string `json:"chain,omitempty"`
	Network   string `json:"network,omitempty"`
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
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
		if req.Network != "" {
			params["network"] = req.Network
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

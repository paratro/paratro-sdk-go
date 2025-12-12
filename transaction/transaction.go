package transaction

import (
	"context"
	"fmt"
	"strconv"

	"github.com/reefiy/mpc-sdk-go/common"
)

// Service handles transaction-related API operations
type Service struct {
	client *common.Client
}

// NewService creates a new transaction service
func NewService(client *common.Client) *Service {
	return &Service{client: client}
}

// Transaction represents a blockchain transaction
type Transaction struct {
	TxID            string `json:"tx_id"`
	WalletID        string `json:"wallet_id"`
	AccountID       string `json:"account_id"`
	AssetID         string `json:"asset_id,omitempty"`
	FromAddress     string `json:"from_address"`
	ToAddress       string `json:"to_address"`
	Amount          string `json:"amount"`
	Fee             string `json:"fee"`
	Chain           string `json:"chain"`
	Network         string `json:"network"`
	TxHash          string `json:"tx_hash"`
	BlockNumber     int64  `json:"block_number"`
	Confirmations   int    `json:"confirmations"`
	Status          string `json:"status"`  // PENDING, CONFIRMING, CONFIRMED, FAILED
	TxType          string `json:"tx_type"` // SEND, RECEIVE
	ContractAddress string `json:"contract_address,omitempty"`
	Memo            string `json:"memo,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at,omitempty"`
	ConfirmedAt     string `json:"confirmed_at,omitempty"`
}

// Get retrieves a transaction by ID
func (s *Service) Get(ctx context.Context, txID string) (*Transaction, error) {
	var transaction Transaction
	path := fmt.Sprintf("/api/v1/transactions/%s", txID)
	err := s.client.Request("GET", path, nil, &transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	return &transaction, nil
}

// ListTransactionsRequest represents a request to list transactions
type ListTransactionsRequest struct {
	WalletID  string `json:"wallet_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
}

// ListTransactionsResponse represents a paginated list of transactions
type ListTransactionsResponse struct {
	Items      []*Transaction `json:"items"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalCount int            `json:"total_count"`
	TotalPages int            `json:"total_pages"`
}

// List retrieves a list of transactions
func (s *Service) List(ctx context.Context, req *ListTransactionsRequest) (*ListTransactionsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.WalletID != "" {
			params["wallet_id"] = req.WalletID
		}
		if req.AccountID != "" {
			params["account_id"] = req.AccountID
		}
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

	var transactions []*Transaction
	err := s.client.RequestWithQuery("/api/v1/transactions", params, &transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to list transactions: %v", err)
	}
	return &ListTransactionsResponse{
		Items: transactions,
	}, nil
}

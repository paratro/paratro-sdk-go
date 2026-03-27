package paratro

import (
	"context"
	"fmt"
	"strconv"
)

// CreateAccountRequest represents a request to create a new account
type CreateAccountRequest struct {
	WalletID    string `json:"wallet_id"`
	Chain       string `json:"chain"`
	AccountType string `json:"account_type,omitempty"`
	Label       string `json:"label,omitempty"`
}

// Account represents an account in a wallet
type Account struct {
	AccountID   string `json:"account_id"`
	WalletID    string `json:"wallet_id"`
	ClientID    string `json:"client_id"`
	Address     string `json:"address"`
	Network     string `json:"network"`
	AddressType string `json:"address_type"`
	Label       string `json:"label"`
	Status      string `json:"status"` // ACTIVE, INACTIVE, etc.
	CreatedAt   string `json:"created_at"`
}

// CreateAccount creates a new account in a wallet
func (s *service) CreateAccount(ctx context.Context, req *CreateAccountRequest) (*Account, error) {
	var account Account
	err := s.client.request(ctx, "POST", "/api/v1/accounts", req, &account)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}
	return &account, nil
}

// GetAccount retrieves an account by ID
func (s *service) GetAccount(ctx context.Context, accountID string) (*Account, error) {
	var account Account
	path := fmt.Sprintf("/api/v1/accounts/%s", accountID)
	err := s.client.request(ctx, "GET", path, nil, &account)
	if err != nil {
		return nil, fmt.Errorf("failed to get account: %w", err)
	}
	return &account, nil
}

// ListAccountsRequest represents a request to list accounts
type ListAccountsRequest struct {
	WalletID string `json:"wallet_id,omitempty"` // Filter by wallet ID
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
}

// ListAccountsResponse represents a paginated list of accounts
type ListAccountsResponse struct {
	Items   []*Account `json:"data"`
	Total   int64      `json:"total"`
	HasMore bool       `json:"has_more"`
}

// ListAccounts retrieves a list of accounts
func (s *service) ListAccounts(ctx context.Context, req *ListAccountsRequest) (*ListAccountsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.WalletID != "" {
			params["wallet_id"] = req.WalletID
		}
		if req.Page > 0 {
			params["page"] = strconv.Itoa(req.Page)
		}
		if req.PageSize > 0 {
			params["page_size"] = strconv.Itoa(req.PageSize)
		}
	}

	var response ListAccountsResponse
	err := s.client.requestWithQuery(ctx, "/api/v1/accounts", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}
	return &response, nil
}

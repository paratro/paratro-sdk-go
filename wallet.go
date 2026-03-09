package paratro

import (
	"context"
	"fmt"
	"strconv"
)

// CreateWalletRequest represents a request to create a new MPC wallet
type CreateWalletRequest struct {
	WalletName  string `json:"wallet_name"`
	Description string `json:"description,omitempty"`
}

// Wallet represents an MPC wallet
type Wallet struct {
	WalletID    string `json:"wallet_id"`
	ClientID    string `json:"client_id"`
	WalletName  string `json:"wallet_name"`
	Description string `json:"description"`
	Status      string `json:"status"`     // ACTIVE, INACTIVE, etc.
	KeyStatus   string `json:"key_status"` // READY, PENDING, etc.
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// CreateWallet creates a new MPC wallet
func (s *service) CreateWallet(ctx context.Context, req *CreateWalletRequest) (*Wallet, error) {
	var wallet Wallet
	err := s.client.request(ctx, "POST", "/api/v1/wallets", req, &wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}
	return &wallet, nil
}

// GetWallet retrieves a wallet by ID
func (s *service) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	var wallet Wallet
	path := fmt.Sprintf("/api/v1/wallets/%s", walletID)
	err := s.client.request(ctx, "GET", path, nil, &wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	return &wallet, nil
}

// ListWalletsRequest represents a request to list wallets
type ListWalletsRequest struct {
	Page     int `json:"page,omitempty"`
	PageSize int `json:"page_size,omitempty"`
}

// ListWalletsResponse represents a paginated list of wallets
type ListWalletsResponse struct {
	Items   []*Wallet `json:"data"`
	Total   int64     `json:"total"`
	HasMore bool      `json:"has_more"`
}

// ListWallets retrieves a list of wallets
func (s *service) ListWallets(ctx context.Context, req *ListWalletsRequest) (*ListWalletsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.Page > 0 {
			params["page"] = strconv.Itoa(req.Page)
		}
		if req.PageSize > 0 {
			params["page_size"] = strconv.Itoa(req.PageSize)
		}
	}

	var response ListWalletsResponse
	err := s.client.requestWithQuery(ctx, "/api/v1/wallets", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list wallets: %w", err)
	}

	return &response, nil
}

package wallet

import (
	"context"
	"fmt"
	"strconv"

	"github.com/reefiy/mpc-sdk-go/common"
)

// Service handles wallet-related API operations
type Service struct {
	client *common.Client
}

// NewService creates a new wallet service
func NewService(client *common.Client) *Service {
	return &Service{client: client}
}

// CreateWalletRequest represents a request to create a new MPC wallet
type CreateWalletRequest struct {
	WalletName  string `json:"wallet_name"`
	Description string `json:"description,omitempty"`
	Chain       string `json:"chain"`   // ETH, TRX, BTC, etc.
	Network     string `json:"network"` // mainnet, testnet
}

// Wallet represents an MPC wallet
type Wallet struct {
	WalletID    string `json:"wallet_id"`
	WalletName  string `json:"wallet_name"`
	Description string `json:"description"`
	Chain       string `json:"chain"`
	Network     string `json:"network"`
	WalletType  string `json:"wallet_type"` // MPC
	Status      string `json:"status"`      // PENDING, ACTIVE, FROZEN, DELETED
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// Create creates a new MPC wallet
func (s *Service) Create(ctx context.Context, req *CreateWalletRequest) (*Wallet, error) {
	var wallet Wallet
	err := s.client.Request("POST", "/api/v1/wallets", req, &wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}
	return &wallet, nil
}

// Get retrieves a wallet by ID
func (s *Service) Get(ctx context.Context, walletID string) (*Wallet, error) {
	var wallet Wallet
	path := fmt.Sprintf("/api/v1/wallets/%s", walletID)
	err := s.client.Request("GET", path, nil, &wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	return &wallet, nil
}

// ListWalletsRequest represents a request to list wallets
type ListWalletsRequest struct {
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
	Status   string `json:"status,omitempty"`
}

// ListWalletsResponse represents a paginated list of wallets
type ListWalletsResponse struct {
	Items []*Wallet `json:"data"`
}

// List retrieves a list of wallets
func (s *Service) List(ctx context.Context, req *ListWalletsRequest) (*ListWalletsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.Page > 0 {
			params["page"] = strconv.Itoa(req.Page)
		}
		if req.PageSize > 0 {
			params["page_size"] = strconv.Itoa(req.PageSize)
		}
		if req.Status != "" {
			params["status"] = req.Status
		}
	}

	var response []*Wallet
	err := s.client.RequestWithQuery("/api/v1/wallets", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list wallets: %w", err)
	}

	return &ListWalletsResponse{
		Items: response,
	}, nil
}

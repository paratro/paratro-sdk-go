package account

import (
	"context"
	"fmt"
	"strconv"

	"github.com/reefiy/mpc-sdk-go/common"
)

// Service handles account-related API operations
type Service struct {
	client *common.Client
}

// NewService creates a new account service
func NewService(client *common.Client) *Service {
	return &Service{client: client}
}

// CreateAccountRequest represents a request to create a new account
type CreateAccountRequest struct {
	WalletID    string `json:"wallet_id"`
	Chain       string `json:"chain"`
	Network     string `json:"network"`
	Label       string `json:"label,omitempty"`
	AccountType string `json:"account_type,omitempty"` // EOA, etc.
}

// Account represents an account in a wallet
type Account struct {
	AccountID      string `json:"account_id"`
	WalletID       string `json:"wallet_id"`
	Address        string `json:"address"`
	Chain          string `json:"chain"`
	Network        string `json:"network"`
	Label          string `json:"label"`
	DerivationPath string `json:"derivation_path"`
	AddressIndex   int    `json:"address_index"`
	Status         string `json:"status"` // ACTIVE, FROZEN, DELETED
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

// Create creates a new account in a wallet
func (s *Service) Create(ctx context.Context, req *CreateAccountRequest) (*Account, error) {
	var account Account
	err := s.client.Request("POST", "/api/v1/accounts", req, &account)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}
	return &account, nil
}

// Get retrieves an account by ID
func (s *Service) Get(ctx context.Context, accountID string) (*Account, error) {
	var account Account
	path := fmt.Sprintf("/api/v1/accounts/%s", accountID)
	err := s.client.Request("GET", path, nil, &account)
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
	Items      []Account `json:"items"`
	Page       int       `json:"page"`
	PageSize   int       `json:"page_size"`
	TotalCount int       `json:"total_count"`
	TotalPages int       `json:"total_pages"`
}

// List retrieves a list of accounts
func (s *Service) List(ctx context.Context, req *ListAccountsRequest) (*ListAccountsResponse, error) {
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
	err := s.client.RequestWithQuery("/api/v1/accounts", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}
	return &response, nil
}

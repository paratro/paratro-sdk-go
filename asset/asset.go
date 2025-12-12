package asset

import (
	"context"
	"fmt"
	"strconv"

	"github.com/reefiy/mpc-sdk-go/common"
)

// Service handles asset-related API operations
type Service struct {
	client *common.Client
}

// NewService creates a new asset service
func NewService(client *common.Client) *Service {
	return &Service{client: client}
}

// CreateAssetRequest represents a request to add a new asset
type CreateAssetRequest struct {
	WalletID        string `json:"wallet_id"`
	AccountID       string `json:"account_id"`
	Chain           string `json:"chain"`
	Network         string `json:"network"`
	Symbol          string `json:"symbol"`
	Name            string `json:"name"`
	AssetType       string `json:"asset_type"`                 // NATIVE, ERC20, TRC20, etc.
	ContractAddress string `json:"contract_address,omitempty"` // For tokens
	Decimals        int    `json:"decimals"`
}

// Asset represents an asset (token) in an account
type Asset struct {
	AssetID         string `json:"asset_id"`
	WalletID        string `json:"wallet_id"`
	AccountID       string `json:"account_id"`
	Symbol          string `json:"symbol"`
	Name            string `json:"name"`
	AssetType       string `json:"asset_type"`
	ContractAddress string `json:"contract_address"`
	Decimals        int    `json:"decimals"`
	Balance         string `json:"balance"`
	Status          string `json:"status"` // ACTIVE, INACTIVE
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

// Create creates a new asset for an account
func (s *Service) Create(ctx context.Context, req *CreateAssetRequest) (*Asset, error) {
	var asset Asset
	err := s.client.Request("POST", "/api/v1/assets", req, &asset)
	if err != nil {
		return nil, fmt.Errorf("failed to create asset: %w", err)
	}
	return &asset, nil
}

// Get retrieves an asset by ID
func (s *Service) Get(ctx context.Context, assetID string) (*Asset, error) {
	var asset Asset
	path := fmt.Sprintf("/api/v1/assets/%s", assetID)
	err := s.client.Request("GET", path, nil, &asset)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	return &asset, nil
}

// ListAssetsRequest represents a request to list assets
type ListAssetsRequest struct {
	WalletID  string `json:"wallet_id,omitempty"`  // Filter by wallet ID
	AccountID string `json:"account_id,omitempty"` // Filter by account ID
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
}

// ListAssetsResponse represents a paginated list of assets
type ListAssetsResponse struct {
	Items      []*Asset `json:"items"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	TotalCount int      `json:"total_count"`
	TotalPages int      `json:"total_pages"`
}

// List retrieves a list of assets
func (s *Service) List(ctx context.Context, req *ListAssetsRequest) (*ListAssetsResponse, error) {
	params := make(map[string]string)

	if req != nil {
		if req.WalletID != "" {
			params["wallet_id"] = req.WalletID
		}
		if req.AccountID != "" {
			params["account_id"] = req.AccountID
		}
		if req.Page > 0 {
			params["page"] = strconv.Itoa(req.Page)
		}
		if req.PageSize > 0 {
			params["page_size"] = strconv.Itoa(req.PageSize)
		}
	}

	var assets []*Asset
	err := s.client.RequestWithQuery("/api/v1/assets", params, &assets)
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	return &ListAssetsResponse{
		Items: assets,
	}, nil
}

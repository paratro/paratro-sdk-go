package paratro

import (
	"context"
	"fmt"
	"strconv"
)

// CreateAssetRequest represents a request to add a new asset
type CreateAssetRequest struct {
	AccountID string `json:"account_id"`
	Symbol    string `json:"symbol"`
	Chain     string `json:"chain,omitempty"` // Required for EVM accounts to specify target chain
}

// Asset represents an asset (token) in an account
type Asset struct {
	AssetID         string `json:"asset_id"`
	AccountID       string `json:"account_id"`
	WalletID        string `json:"wallet_id"`
	ClientID        string `json:"client_id"`
	Chain           string `json:"chain"`
	Network         string `json:"network"`
	Symbol          string `json:"symbol"`
	Name            string `json:"name"`
	ContractAddress string `json:"contract_address"`
	Decimals        int    `json:"decimals"`
	AssetType       string `json:"asset_type"`
	Balance         string `json:"balance"`
	LockedBalance   string `json:"locked_balance"`
	IsActive        bool   `json:"is_active"`
	CreatedAt       string `json:"created_at"`
}

// CreateAsset creates a new asset for an account
func (s *service) CreateAsset(ctx context.Context, req *CreateAssetRequest) (*Asset, error) {
	var asset Asset
	err := s.client.request(ctx, "POST", "/api/v1/assets", req, &asset)
	if err != nil {
		return nil, fmt.Errorf("failed to create asset: %w", err)
	}
	return &asset, nil
}

// GetAsset retrieves an asset by ID
func (s *service) GetAsset(ctx context.Context, assetID string) (*Asset, error) {
	var asset Asset
	path := fmt.Sprintf("/api/v1/assets/%s", assetID)
	err := s.client.request(ctx, "GET", path, nil, &asset)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	return &asset, nil
}

// ListAssetsRequest represents a request to list assets
type ListAssetsRequest struct {
	AccountID string `json:"account_id,omitempty"` // Filter by account ID
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
}

// ListAssetsResponse represents a paginated list of assets
type ListAssetsResponse struct {
	Items   []*Asset `json:"data"`
	Total   int64    `json:"total"`
	HasMore bool     `json:"has_more"`
}

// ListAssets retrieves a list of assets
func (s *service) ListAssets(ctx context.Context, req *ListAssetsRequest) (*ListAssetsResponse, error) {
	params := make(map[string]string)

	if req != nil {
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

	var response ListAssetsResponse
	err := s.client.requestWithQuery(ctx, "/api/v1/assets", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	return &response, nil
}

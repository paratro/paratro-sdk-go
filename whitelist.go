package paratro

import (
	"context"
	"fmt"
)

// TransferWhitelistItem represents a whitelisted transfer address.
type TransferWhitelistItem struct {
	WhitelistID string `json:"whitelist_id"`
	Chain       string `json:"chain"`
	Address     string `json:"address"`
	Label       string `json:"label"`
	AddedBy     string `json:"added_by"`
	CreatedAt   string `json:"created_at"`
}

// ListWhitelistResponse represents a list of whitelisted addresses.
type ListWhitelistResponse struct {
	Items []TransferWhitelistItem `json:"items"`
	Total int64                   `json:"total"`
}

// AddWhitelistRequest represents a request to add an address to the whitelist.
type AddWhitelistRequest struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
	MFACode string `json:"mfa_code"`
}

// DeleteWhitelistRequest represents a request to delete a whitelisted address.
type DeleteWhitelistRequest struct {
	MFACode string `json:"mfa_code"`
}

// ListWhitelist retrieves the transfer whitelist, optionally filtered by chain.
func (s *service) ListWhitelist(ctx context.Context, chain string) (*ListWhitelistResponse, error) {
	params := make(map[string]string)
	if chain != "" {
		params["chain"] = chain
	}

	var response ListWhitelistResponse
	err := s.client.requestWithQuery(ctx, "/v1/client/whitelist", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list whitelist: %w", err)
	}
	return &response, nil
}

// AddWhitelist adds an address to the transfer whitelist.
func (s *service) AddWhitelist(ctx context.Context, req *AddWhitelistRequest) (*TransferWhitelistItem, error) {
	var item TransferWhitelistItem
	err := s.client.request(ctx, "POST", "/v1/client/whitelist", req, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to add whitelist entry: %w", err)
	}
	return &item, nil
}

// DeleteWhitelist removes an address from the transfer whitelist.
func (s *service) DeleteWhitelist(ctx context.Context, whitelistID string, req *DeleteWhitelistRequest) error {
	path := fmt.Sprintf("/v1/client/whitelist/%s", whitelistID)
	err := s.client.request(ctx, "DELETE", path, req, nil)
	if err != nil {
		return fmt.Errorf("failed to delete whitelist entry: %w", err)
	}
	return nil
}

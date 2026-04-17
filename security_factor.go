package paratro

import (
	"context"
	"fmt"
)

// SecurityFactorItem represents a security factor entry (e.g. whitelisted address).
type SecurityFactorItem struct {
	WhitelistID string `json:"whitelist_id"`
	Chain       string `json:"chain"`
	Address     string `json:"address"`
	Label       string `json:"label"`
	FactorType  string `json:"factor_type"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	AddedBy     string `json:"added_by"`
	CreatedAt   string `json:"created_at"`
}

// ListSecurityFactorResponse represents a list of security factor entries.
type ListSecurityFactorResponse struct {
	Items []SecurityFactorItem `json:"items"`
	Total int64                `json:"total"`
}

// AddSecurityFactorRequest represents a request to add a security factor entry.
type AddSecurityFactorRequest struct {
	Chain      string `json:"chain"`
	Address    string `json:"address"`
	Label      string `json:"label,omitempty"`
	FactorType string `json:"factor_type"`
	Reason     string `json:"reason,omitempty"`
	MFACode    string `json:"mfa_code"`
}

// DeleteSecurityFactorRequest represents a request to delete a security factor entry.
type DeleteSecurityFactorRequest struct {
	MFACode string `json:"mfa_code"`
}

// SetSecurityFactorStatusRequest represents a request to update the status of a security factor.
type SetSecurityFactorStatusRequest struct {
	Status  string `json:"status"`
	MFACode string `json:"mfa_code"`
}

// ListSecurityFactors retrieves security factors, optionally filtered by chain.
func (s *service) ListSecurityFactors(ctx context.Context, chain string) (*ListSecurityFactorResponse, error) {
	params := make(map[string]string)
	if chain != "" {
		params["chain"] = chain
	}

	var response ListSecurityFactorResponse
	err := s.client.requestWithQuery(ctx, "/v1/client/security-factors", params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list security factors: %w", err)
	}
	return &response, nil
}

// AddSecurityFactor adds a new security factor entry.
func (s *service) AddSecurityFactor(ctx context.Context, req *AddSecurityFactorRequest) (*SecurityFactorItem, error) {
	var item SecurityFactorItem
	err := s.client.request(ctx, "POST", "/v1/client/security-factors", req, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to add security factor: %w", err)
	}
	return &item, nil
}

// DeleteSecurityFactor removes a security factor entry.
func (s *service) DeleteSecurityFactor(ctx context.Context, factorID string, req *DeleteSecurityFactorRequest) error {
	path := fmt.Sprintf("/v1/client/security-factors/%s", factorID)
	err := s.client.request(ctx, "DELETE", path, req, nil)
	if err != nil {
		return fmt.Errorf("failed to delete security factor: %w", err)
	}
	return nil
}

// SetSecurityFactorStatus updates the status of a security factor entry.
func (s *service) SetSecurityFactorStatus(ctx context.Context, factorID string, req *SetSecurityFactorStatusRequest) error {
	path := fmt.Sprintf("/v1/client/security-factors/%s/status", factorID)
	err := s.client.request(ctx, "PUT", path, req, nil)
	if err != nil {
		return fmt.Errorf("failed to set security factor status: %w", err)
	}
	return nil
}

package mpcsdk

import (
	"fmt"

	"github.com/reefiy/mpc-sdk-go/account"
	"github.com/reefiy/mpc-sdk-go/asset"
	"github.com/reefiy/mpc-sdk-go/auth"
	"github.com/reefiy/mpc-sdk-go/common"
	"github.com/reefiy/mpc-sdk-go/configuration"
	"github.com/reefiy/mpc-sdk-go/transaction"
	"github.com/reefiy/mpc-sdk-go/wallet"
)

// Client is the main MPC SDK client
type Client struct {
	config       *configuration.Config
	tokenManager *auth.TokenManager
	apiClient    *common.Client

	// Services
	Wallet      *wallet.Service
	Account     *account.Service
	Asset       *asset.Service
	Transaction *transaction.Service
}

// NewClient creates a new MPC SDK client
func NewClient(apiKey, apiSecret string, config *configuration.Config) (*Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("apiKey is required")
	}
	if apiSecret == "" {
		return nil, fmt.Errorf("apiSecret is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Create token manager
	tokenManager := auth.NewTokenManager(apiKey, apiSecret, config.BaseURL)

	// Create API client
	apiClient := common.NewClient(config.BaseURL, tokenManager)

	// Create client with services
	client := &Client{
		config:       config,
		tokenManager: tokenManager,
		apiClient:    apiClient,
		Wallet:       wallet.NewService(apiClient),
		Account:      account.NewService(apiClient),
		Asset:        asset.NewService(apiClient),
		Transaction:  transaction.NewService(apiClient),
	}

	return client, nil
}

// GetConfig returns the client configuration
func (c *Client) GetConfig() *configuration.Config {
	return c.config
}

// Logout logs out from the API
func (c *Client) Logout() error {
	return c.tokenManager.Logout()
}

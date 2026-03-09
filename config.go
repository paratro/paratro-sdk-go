package paratro

// Config holds the configuration for the MPC SDK
type Config struct {
	BaseURL string
}

// Sandbox returns configuration for the sandbox environment
func Sandbox() *Config {
	return &Config{
		BaseURL: "https://api-sandbox.paratro.com",
	}
}

// Production returns configuration for the production environment
func Production() *Config {
	return &Config{
		BaseURL: "https://api.paratro.com",
	}
}

// Custom returns a custom configuration with the specified base URL
func Custom(baseURL string) *Config {
	return &Config{
		BaseURL: baseURL,
	}
}

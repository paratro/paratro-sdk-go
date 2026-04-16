package paratro

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// Webhook event type constants.
const (
	EventTransactionConfirming   = "transaction.confirming"
	EventTransactionConfirmed    = "transaction.confirmed"
	EventTransactionFailed       = "transaction.failed"
	EventX402SettlementConfirmed = "x402.settlement.confirmed"
	EventX402SettlementFailed    = "x402.settlement.failed"
)

// DefaultWebhookTolerance is the default time tolerance for webhook signatures (5 minutes).
const DefaultWebhookTolerance = 5 * time.Minute

// WebhookEvent represents a parsed webhook payload (v2 schema).
type WebhookEvent struct {
	EventID               string  `json:"event_id"`
	EventType             string  `json:"event_type"`
	EventTime             string  `json:"event_time"`
	SourceID              string  `json:"source_id"`
	WalletID              string  `json:"wallet_id"`
	AccountID             string  `json:"account_id"`
	Status                string  `json:"status"`
	TransactionType       string  `json:"transaction_type"`
	Chain                 string  `json:"chain"`
	Network               string  `json:"network"`
	TxHash                string  `json:"txhash"`
	BlockNumber           uint64  `json:"block_number"`
	From                  string  `json:"from"`
	To                    string  `json:"to"`
	Symbol                string  `json:"symbol"`
	ContractAddress       string  `json:"contract_address"`
	Amount                string  `json:"amount"`
	Decimals              int     `json:"decimals"`
	Confirmations         uint64  `json:"confirmations"`
	RequiredConfirmations uint64  `json:"required_confirmations"`
	CreatedAt             string  `json:"created_at"`
	ConfirmedAt           *string `json:"confirmed_at"`
	RiskChecked           bool    `json:"risk_checked"`
	RiskScore             float64 `json:"risk_score"`
	RiskLevel             string  `json:"risk_level"`
	Data                  string  `json:"data"`
}

// VerifyWebhookSignature verifies the HMAC-SHA256 signature of a webhook request.
// Returns nil if valid, error otherwise.
func VerifyWebhookSignature(secret, timestamp string, payload []byte, signature string, tolerance time.Duration) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("webhook: invalid timestamp: %w", err)
	}

	if tolerance > 0 {
		diff := time.Duration(math.Abs(float64(time.Now().Unix()-ts))) * time.Second
		if diff > tolerance {
			return fmt.Errorf("webhook: timestamp too old (age: %v, tolerance: %v)", diff, tolerance)
		}
	}

	canonical := []byte(fmt.Sprintf("%s.%s", timestamp, payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	expected := "v1=" + hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("webhook: signature mismatch")
	}
	return nil
}

// ParseWebhookEvent parses a raw JSON body into a WebhookEvent.
func ParseWebhookEvent(body []byte) (*WebhookEvent, error) {
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, fmt.Errorf("webhook: failed to parse event: %w", err)
	}
	return &event, nil
}

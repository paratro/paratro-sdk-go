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
	EventTransactionConfirming = "transaction.confirming"
	EventTransactionConfirmed  = "transaction.confirmed"
	EventTransactionFailed     = "transaction.failed"
)

// DefaultWebhookTolerance is the default time tolerance for webhook signatures (5 minutes).
const DefaultWebhookTolerance = 5 * time.Minute

// WebhookEvent represents a parsed webhook payload.
type WebhookEvent struct {
	ID                    string `json:"id"`
	EventType             string `json:"event_type"`
	Chain                 string `json:"chain"`
	TxHash                string `json:"txhash"`
	Type                  string `json:"type"`      // transfer, erc20_transfer, etc.
	Status                string `json:"status"`    // CONFIRMING, CONFIRMED, FAILED
	Direction             string `json:"direction"` // INBOUND, OUTBOUND
	From                  string `json:"from"`
	To                    string `json:"to"`
	Symbol                string `json:"symbol"`
	Amount                string `json:"amount"`
	Decimals              int    `json:"decimals"`
	BlockNumber           int64  `json:"block_number"`
	Confirmations         int    `json:"confirmations"`
	RequiredConfirmations int    `json:"required_confirmations"`
	TransactionType       string `json:"transaction_type"`
	Data                  string `json:"data"`
	RiskScore             int    `json:"risk_score"`
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

// Command operations shows the unified entry POST /api/v1/transactions with
// each of the three operations (TRANSFER, PROGRAM_CALL, CONTRACT_CALL), how to
// treat a 202 (outcome unknown → poll by tx_id), and how to branch on the
// machine-readable rejection reason of a 400 "Rejected: <tag>: …".
//
// It only sends the operation you select, so it can be pointed at a sandbox
// wallet that has an OPERATION_RULES policy without spending anything by
// accident:
//
//	export PARATRO_API_KEY=... PARATRO_API_SECRET=...
//	export PARATRO_ENV=sandbox                # or production
//	export PARATRO_FROM=<your paying wallet address>
//
//	# TRANSFER
//	export PARATRO_TO=0x... PARATRO_TOKEN=USDC PARATRO_AMOUNT=1.5
//	go run ./examples/operations transfer
//
//	# PROGRAM_CALL (solana): counterparty-signed transaction, base64 or 0x-hex
//	export PARATRO_SIGNED_TX=<base64>
//	go run ./examples/operations program_call
//
//	# CONTRACT_CALL (ethereum): the xChange quote
//	export PARATRO_QUOTE_ID=0x<bytes32> PARATRO_EXPIRATION=<unix seconds>
//	export PARATRO_COUNTERPARTY=0x... PARATRO_PAY_TOKEN=0x... PARATRO_PAY_AMOUNT=10000000
//	export PARATRO_RECV_TOKEN=0x... PARATRO_RECV_AMOUNT=42000000000000000
//	export PARATRO_COUNTERPARTY_SIG=0x<65 bytes>
//	go run ./examples/operations contract_call
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	paratro "github.com/paratro/paratro-sdk-go"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func pretty(v interface{}) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: operations transfer|program_call|contract_call")
		os.Exit(2)
	}
	cfg := paratro.Sandbox()
	if os.Getenv("PARATRO_ENV") == "production" {
		cfg = paratro.Production()
	}
	// PROGRAM_CALL / CONTRACT_CALL hold the connection while the gateway waits
	// for the signing engine (engine budget 120s; the gateway answers 202 after
	// 150s and closes the connection at 180s). cfg.Timeout defaults to
	// paratro.DefaultTimeout (200s); never lower it for these operations.
	client, err := paratro.NewMPCClient(os.Getenv("PARATRO_API_KEY"), os.Getenv("PARATRO_API_SECRET"), cfg)
	if err != nil {
		fmt.Println("client init:", err)
		os.Exit(1)
	}
	ctx := context.Background()

	from := os.Getenv("PARATRO_FROM")
	// reference_id is your business reference: the gateway rejects a reuse
	// with 400 Duplicate reference_id, which is what makes the entry idempotent.
	referenceID := env("PARATRO_REFERENCE_ID", fmt.Sprintf("sdk-example-%d", time.Now().UnixNano()))

	var req paratro.TransactionRequest
	switch os.Args[1] {
	case "transfer":
		req = &paratro.TransferRequest{
			FromAddress: from,
			ToAddress:   os.Getenv("PARATRO_TO"),
			Chain:       env("PARATRO_CHAIN", "ethereum"),
			TokenSymbol: env("PARATRO_TOKEN", "USDC"),
			Amount:      env("PARATRO_AMOUNT", "1.5"), // human-readable decimal
			Memo:        "sdk operations example",
			ReferenceID: referenceID,
		}
	case "program_call":
		req = &paratro.ProgramCallRequest{
			FromAddress:       from, // must be the fee payer with an empty signature slot
			Chain:             "solana",
			SignedTransaction: os.Getenv("PARATRO_SIGNED_TX"),
			ReceiveAddress:    env("PARATRO_RECEIVE", ""), // defaults to from_address
			ReferenceID:       referenceID,
		}
	case "contract_call":
		expiration, _ := strconv.ParseInt(os.Getenv("PARATRO_EXPIRATION"), 10, 64)
		receive := env("PARATRO_RECEIVE", from)
		req = &paratro.ContractCallRequest{
			FromAddress:    from,
			Chain:          env("PARATRO_CHAIN", "ethereum"),
			ReceiveAddress: receive,
			ContractCall: paratro.ContractCall{
				QuoteID:    os.Getenv("PARATRO_QUOTE_ID"),
				Expiration: expiration,
				// Amounts are smallest-unit integers (bUSDC has 6 decimals: "10000000" = 10 bUSDC).
				Incoming: paratro.ContractCallIncomingLeg{
					To:     os.Getenv("PARATRO_COUNTERPARTY"),
					Token:  os.Getenv("PARATRO_PAY_TOKEN"),
					Amount: os.Getenv("PARATRO_PAY_AMOUNT"),
				},
				Outgoing: paratro.ContractCallOutgoingLeg{
					From:   os.Getenv("PARATRO_COUNTERPARTY"),
					To:     receive,
					Token:  os.Getenv("PARATRO_RECV_TOKEN"),
					Amount: os.Getenv("PARATRO_RECV_AMOUNT"),
				},
				CounterpartySignature: os.Getenv("PARATRO_COUNTERPARTY_SIG"),
				// PermitDeadline left 0 → gateway default now + min(max_permit_lifetime_seconds, 300)
			},
			ReferenceID: referenceID,
		}
	default:
		fmt.Println("unknown operation:", os.Args[1])
		os.Exit(2)
	}

	fmt.Printf("→ POST /api/v1/transactions operation=%s reference_id=%s\n", req.Operation(), referenceID)
	resp, err := client.Transaction.CreateTransaction(ctx, req)
	if err != nil {
		handleError(err)
		os.Exit(1)
	}

	fmt.Println("←", pretty(resp))
	switch {
	case resp.Accepted():
		// 202 (or an Idempotency-Key replay of one, which arrives as 200
		// PENDING): the row exists but the signing engine did not answer in
		// time. Do NOT resubmit (neither with the same reference_id — it would
		// be a duplicate — nor with a new one — you might pay twice). Poll.
		fmt.Println("accepted: outcome unknown, polling by tx_id …")
		poll(ctx, client, resp.TxID)
	case resp.Status == paratro.StatusBroadcast:
		fmt.Println("broadcast, tx_hash =", resp.TxHash, "— confirmation arrives via GetTransaction / webhook transaction.confirmed")
	case resp.Status == paratro.StatusPending:
		fmt.Println("queued for asynchronous signing (TRANSFER); follow up with GetTransaction / webhooks")
	}
}

// poll follows a transaction until it leaves PENDING (or we give up).
func poll(ctx context.Context, client *paratro.MPCClient, txID string) {
	for i := 0; i < 20; i++ {
		time.Sleep(3 * time.Second)
		tx, err := client.Transaction.GetTransaction(ctx, txID)
		if err != nil {
			fmt.Println("poll error:", err)
			continue
		}
		fmt.Printf("  %s status=%s tx_hash=%s\n", tx.TxID, tx.Status, tx.TxHash)
		if tx.Status != paratro.StatusPending {
			return
		}
	}
}

// handleError shows every branch a caller of the unified entry should handle.
func handleError(err error) {
	switch {
	case paratro.IsRejected(err):
		// 400 "Rejected: <tag>: <detail>" — the request is well-formed but not
		// allowed. The tag is machine-readable; branch on it. A retry (new
		// quote, raised limit) must use a NEW reference_id: the CONTRACT_CALL
		// post-sign check rejects after the row was created.
		switch tag := paratro.RejectionReason(err); tag {
		case paratro.ReasonExpirationPassed, paratro.ReasonPermitDeadlinePassed:
			fmt.Println("quote expired, fetch a new one:", err)
		case paratro.ReasonLimitPerTransaction, paratro.ReasonLimitDaily, paratro.ReasonLimitNotConfigured:
			fmt.Println("policy limit:", tag, "-", err)
		case paratro.ReasonCounterpartyNotRegistered, paratro.ReasonPaymentTokenNotRegistered,
			paratro.ReasonTargetTokenNotRegistered, paratro.ReasonMintNotRegistered, paratro.ReasonProgramNotAllowed:
			fmt.Println("policy does not allow this counterparty / token / program:", tag)
		default:
			fmt.Println("rejected:", tag, "-", err)
		}
	case paratro.IsDuplicateReferenceID(err):
		// Also what you get when you retry a 503 / 400 with the same
		// reference_id: the earlier attempt left a row behind.
		fmt.Println("reference_id already used — the earlier attempt created a row; retry with a new reference_id if you still want the operation")
	case paratro.IsTransactionFailed(err):
		// 400 transaction_failed: the row was created and then failed in the
		// engine; RejectionReason carries the engine tag when there is one.
		fmt.Println("engine failed the transaction:", paratro.RejectionReason(err), "-", err)
	case paratro.IsInsufficientBalance(err):
		fmt.Println("insufficient balance:", err)
	case paratro.IsAddressBlacklisted(err):
		fmt.Println("403 address_blacklisted: TRANSFER destination is blacklisted:", err)
	case paratro.IsForbidden(err):
		fmt.Println("403: no OPERATION_RULES policy allows this operation on this chain:", err)
	case paratro.IsNotFound(err):
		fmt.Println("404: address / asset is not yours, or the token has not been credited yet:", err)
	case paratro.IsServiceUnavailable(err):
		// 503: engine busy / chain RPC unavailable. Not on chain — but "engine
		// busy" is raised after the row was created and the row keeps the
		// reference_id, so a retry needs a NEW reference_id (the same one
		// answers 400 Duplicate reference_id).
		fmt.Println("503: engine busy or chain RPC unavailable — retry later with a new reference_id:", err)
	case paratro.IsEndpointRetired(err):
		fmt.Println("410: endpoint retired:", err)
	default:
		fmt.Println("error:", err)
	}
}

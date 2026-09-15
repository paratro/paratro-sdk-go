package paratro

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocsDoNotPromiseSameReferenceIDRetry pins the retry story to the
// gateway's behaviour. The gateway raises "engine busy" (503), the engine's
// verdict (400 transaction_failed) and the CONTRACT_CALL post-sign rejection
// (400 Rejected) AFTER the transaction row was inserted; the row keeps the
// reference_id and uk_client_reference (client_id, client_reference_key) does
// not look at status. A doc that says "nothing was created, retry with the
// same reference_id" sends the caller into 400 Duplicate reference_id with no
// way out, so no shipped file may say it.
func TestDocsDoNotPromiseSameReferenceIDRetry(t *testing.T) {
	forbidden := []string{
		"nothing was created",
		"nothing created",
		"same reference_id may be retried",
		"same `reference_id` may be retried",
		"same `reference_id` is fine",
		"retry with the same reference_id",
		"retry later with the same reference_id",
		"同一 reference_id 可重试",
	}
	self := "docs_guard_test.go"
	var offenders []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if (ext != ".go" && ext != ".md") || filepath.Base(path) == self {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			lower := strings.ToLower(line)
			for _, phrase := range forbidden {
				if strings.Contains(lower, strings.ToLower(phrase)) {
					offenders = append(offenders, fmt.Sprintf("%s:%d: %s", path, i+1, strings.TrimSpace(line)))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("docs/comments still promise a same-reference_id retry or 'nothing created':\n  %s", strings.Join(offenders, "\n  "))
	}
}

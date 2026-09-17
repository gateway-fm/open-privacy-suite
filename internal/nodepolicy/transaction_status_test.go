package nodepolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransactionStatusRequiresExactBindingAndCanonicalOutcome(t *testing.T) {
	hash := "0x" + strings.Repeat("11", 32)
	for _, test := range []string{"pending", "included", "wrong_hash", "invalid_created", "pending_created", "produced", "resync"} {
		t.Run(test, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     string   `json:"id"`
					Method string   `json:"method"`
					Params []string `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				if req.Method != "ops_transactionStatus" || len(req.Params) != 1 || req.Params[0] != hash {
					t.Errorf("wrong request %+v", req)
				}
				result := map[string]any{"transaction_hash": hash, "principal_id": "user-a", "org_id": "org-a", "context_id": "context-a", "execution": map[string]any{"status": "pending", "facts_version": uint64(7), "block_hash": nil, "block_number": nil, "reason_code": "", "created": []any{}}}
				outcome := result["execution"].(map[string]any)
				outcome["finalized"], outcome["finalized_block_hash"], outcome["finalized_block_number"] = false, nil, nil
				if test == "included" || test == "invalid_created" {
					outcome["status"] = "included"
					outcome["block_hash"] = hash
					outcome["block_number"] = 1
				}
				if test == "invalid_created" || test == "pending_created" {
					outcome["created"] = []any{map[string]any{"address": "0x" + strings.Repeat("22", 20), "org_id": "foreign", "principal_id": "user-a"}}
				}
				if test == "produced" {
					outcome["status"] = "produced"
				}
				if test == "wrong_hash" {
					result["transaction_hash"] = "0x" + strings.Repeat("00", 32)
				}
				response := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
				if test == "resync" {
					delete(response, "result")
					response["error"] = map[string]any{"code": -32011, "message": "private details"}
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer s.Close()
			client, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			status, err := client.TransactionStatus(context.Background(), hash)
			if test == "pending" || test == "included" {
				if err != nil || status.Execution.Status != test {
					t.Fatalf("status=%+v err=%v", status, err)
				}
			} else if err == nil {
				t.Fatal("invalid status accepted")
			}
			if test == "resync" && err != ErrNodeResync {
				t.Fatalf("resync error not classified: %v", err)
			}
		})
	}
}

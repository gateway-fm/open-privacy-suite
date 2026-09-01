package db

import (
	"context"
	"reflect"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// Single-row vs batch parity (RD-1257 follow-up): the batch variants are
// column-list twins of their single-row counterparts and had drifted the same
// way the *Tx twins did — ListContractGrantsBatch dropped event_rules (grants
// came back EventRules=nil, i.e. deny), GetGroupAccessBatch dropped
// verbose_errors. These tests pin batch output to the single-row output for
// identical fixtures.

func TestListContractGrantsBatch_ParityWithSingle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, groupID := txDivergenceFixtures(t, db, ctx)

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "22222222222222222222222222222222",
		Name:     "Batch Parity Contract",
		Metadata: map[string]any{},
	}
	if err := db.CreateContract(ctx, contract); err != nil {
		t.Fatalf("CreateContract failed: %v", err)
	}

	wildcard := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    groupID,
		Functions:  []rbac.FunctionRule{{Selector: "0xa9059cbb"}},
		EventRules: &rbac.EventRulesField{Wildcard: true},
	}
	if err := db.CreateContractGrant(ctx, wildcard); err != nil {
		t.Fatalf("CreateContractGrant (wildcard) failed: %v", err)
	}

	contract2 := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "33333333333333333333333333333333",
		Name:     "Batch Parity Contract 2",
		Metadata: map[string]any{},
	}
	if err := db.CreateContract(ctx, contract2); err != nil {
		t.Fatalf("CreateContract 2 failed: %v", err)
	}
	allowlist := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract2.ID,
		GroupID:    groupID,
		EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{{
			Topic0: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
			Name:   "Transfer",
		}}},
	}
	if err := db.CreateContractGrant(ctx, allowlist); err != nil {
		t.Fatalf("CreateContractGrant (allowlist) failed: %v", err)
	}

	single, err := db.ListContractGrantsByGroup(ctx, groupID)
	if err != nil {
		t.Fatalf("ListContractGrantsByGroup failed: %v", err)
	}
	batch, err := db.ListContractGrantsBatch(ctx, []string{groupID})
	if err != nil {
		t.Fatalf("ListContractGrantsBatch failed: %v", err)
	}

	if len(single) != 2 {
		t.Fatalf("single-row twin returned %d grants, want 2", len(single))
	}
	if !reflect.DeepEqual(single, batch[groupID]) {
		t.Errorf("batch grants diverge from single-row twin:\n single: %+v\n batch:  %+v",
			describeGrants(single), describeGrants(batch[groupID]))
	}
}

func describeGrants(grants []*rbac.ContractGrant) []rbac.ContractGrant {
	out := make([]rbac.ContractGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, *g)
	}
	return out
}

func TestGetGroupAccessBatch_ParityWithSingle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	_, groupID := txDivergenceFixtures(t, db, ctx)

	apiKey := "batch-parity-key"
	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		AllowedMethods: []string{"eth_blockNumber", "eth_chainId"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
		RPCAPIKey:      &apiKey,
		VerboseErrors:  true,
	}
	if err := db.CreateGroupAccess(ctx, access); err != nil {
		t.Fatalf("CreateGroupAccess failed: %v", err)
	}

	single, err := db.GetGroupAccess(ctx, groupID)
	if err != nil {
		t.Fatalf("GetGroupAccess failed: %v", err)
	}
	if single == nil {
		t.Fatal("GetGroupAccess returned nil for existing access")
	}
	batch, err := db.GetGroupAccessBatch(ctx, []string{groupID})
	if err != nil {
		t.Fatalf("GetGroupAccessBatch failed: %v", err)
	}
	got := batch[groupID]
	if got == nil {
		t.Fatal("GetGroupAccessBatch missing the group")
	}

	if !reflect.DeepEqual(single, got) {
		t.Errorf("batch access diverges from single-row twin:\n single: %+v\n batch:  %+v", *single, *got)
	}
}

package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// These tests pin *Tx methods to the behavior of their *DB counterparts
// (RD-1257). Each covers a spot where the hand-copied Tx SQL had silently
// diverged from the DB version: dropped columns on INSERT, missing columns
// on SELECT, or skipped input normalization. The shared-querier dedupe makes
// a recurrence structurally impossible; these tests document the contract.

// txDivergenceFixtures creates an org and a group to hang test rows off.
func txDivergenceFixtures(t *testing.T, db *DB, ctx context.Context) (orgID, groupID string) {
	t.Helper()
	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "twin-org-" + uuid.New().String()[:8],
		Name:     "Twin Divergence Org",
		Settings: map[string]any{},
	}
	if err := db.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}
	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "twin-group-" + uuid.New().String()[:8],
		Name:  "Twin Divergence Group",
		Depth: 0,
		Path:  "twin",
	}
	if err := db.CreateGroup(ctx, group); err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	return org.ID, group.ID
}

// user_memberships.expires_at is a plain TIMESTAMP: whatever wall-clock the
// driver sends is what NOW() (UTC session) is compared against. The DB path
// converts to UTC first (utcPtr, RD-1005); the tx path must do the same, or
// a membership written in a non-UTC process timezone expires at the wrong
// instant (fail-open for zones east of UTC).
func TestTxCreateMembership_NormalizesExpiresAtUTC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	_, groupID := txDivergenceFixtures(t, db, ctx)

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:twin-utc-" + uuid.New().String()[:8],
		Metadata:   map[string]any{},
	}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// +10h zone: wall clock is 10h ahead of UTC, so storing the un-normalized
	// wall clock makes the membership look active 10h longer than granted.
	east := time.FixedZone("UTC+10", 10*3600)
	expires := time.Date(2027, 3, 1, 12, 0, 0, 0, east) // = 02:00 UTC

	for _, tc := range []struct {
		name   string
		create func(m *rbac.UserMembership) error
	}{
		{"db path", func(m *rbac.UserMembership) error {
			return db.CreateMembership(ctx, m)
		}},
		{"tx path", func(m *rbac.UserMembership) error {
			return db.WithTx(ctx, func(tx *Tx) error { return tx.CreateMembership(ctx, m) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &rbac.UserMembership{
				ID:        uuid.New().String(),
				UserID:    user.ID,
				GroupID:   groupID,
				Source:    rbac.MembershipSourceAdmin,
				ExpiresAt: &expires,
			}
			if err := tc.create(m); err != nil {
				t.Fatalf("create membership failed: %v", err)
			}
			t.Cleanup(func() { _ = db.DeleteMembership(ctx, m.ID) })

			found, err := db.GetMembership(ctx, m.ID)
			if err != nil {
				t.Fatalf("GetMembership failed: %v", err)
			}
			if found == nil || found.ExpiresAt == nil {
				t.Fatal("membership or expires_at missing after round-trip")
			}
			if !found.ExpiresAt.Equal(expires) {
				t.Errorf("expires_at instant skewed: stored %v, want instant %v (UTC %v) — tx path must UTC-normalize like the DB path",
					found.ExpiresAt, expires, expires.UTC())
			}
		})
	}
}

// The contract SELECT twins must return every column the DB versions return.
// The tx copies had dropped abi and events_allow_dynamic_payload.
func TestTxContractReads_IncludeABIAndDynamicPayloadFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, _ := txDivergenceFixtures(t, db, ctx)

	const abi = `[{"type":"function","name":"twinCheck"}]`
	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "00000000000000000000000000000000",
		Name:     "Twin Read Contract",
		ABI:      abi,
		Metadata: map[string]any{},
	}
	if err := db.CreateContract(ctx, contract); err != nil {
		t.Fatalf("CreateContract failed: %v", err)
	}
	if err := db.UpdateContractEventsAllowDynamicPayload(ctx, contract.ID, true); err != nil {
		t.Fatalf("UpdateContractEventsAllowDynamicPayload failed: %v", err)
	}

	// No t.Fatal inside the WithTx callback: FailNow exits the goroutine
	// before WithTx can roll back or commit, leaking the open transaction.
	// The callback only collects; assertions run after WithTx returns.
	var byID, byAddr *rbac.Contract
	var byIDs map[string]*rbac.Contract
	err := db.WithTx(ctx, func(tx *Tx) error {
		var err error
		if byID, err = tx.GetContract(ctx, contract.ID); err != nil {
			return fmt.Errorf("tx.GetContract: %w", err)
		}
		if byAddr, err = tx.GetContractByAddress(ctx, orgID, contract.Address); err != nil {
			return fmt.Errorf("tx.GetContractByAddress: %w", err)
		}
		if byIDs, err = tx.GetContractsByIDs(ctx, []string{contract.ID}); err != nil {
			return fmt.Errorf("tx.GetContractsByIDs: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx failed: %v", err)
	}

	for name, got := range map[string]*rbac.Contract{
		"GetContract":          byID,
		"GetContractByAddress": byAddr,
		"GetContractsByIDs":    byIDs[contract.ID],
	} {
		if got == nil {
			t.Fatalf("tx.%s returned nil for existing contract", name)
		}
		if got.ABI != abi {
			t.Errorf("tx.%s dropped abi: got %q", name, got.ABI)
		}
		if !got.EventsAllowDynamicPayload {
			t.Errorf("tx.%s dropped events_allow_dynamic_payload", name)
		}
	}
}

// The tx INSERT twin had dropped the abi column: any contract created through
// the tx path lost its ABI. Today that path is reached only via the
// CreateContractWithGrant composite (tx_operations.go), which has no
// production callers yet — a landmine for its first one rather than live
// data loss.
func TestTxCreateContract_PersistsABI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, _ := txDivergenceFixtures(t, db, ctx)

	const abi = `[{"type":"function","name":"txCreate"}]`
	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "11111111111111111111111111111111",
		Name:     "Twin Create Contract",
		ABI:      abi,
		Metadata: map[string]any{},
	}
	err := db.WithTx(ctx, func(tx *Tx) error { return tx.CreateContract(ctx, contract) })
	if err != nil {
		t.Fatalf("tx.CreateContract failed: %v", err)
	}

	found, err := db.GetContract(ctx, contract.ID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if found == nil {
		t.Fatal("contract missing after tx create")
	}
	if found.ABI != abi {
		t.Errorf("abi lost through tx create path: got %q, want %q", found.ABI, abi)
	}
}

// The group twins had dropped is_org_readonly_admin (INSERT + SELECT) and
// is_system (SELECT). batchDeleteGroups gates the RD-1107 operator-token rule
// on exactly these two flags read through tx.GetGroupsByIDs, so the dropped
// columns made super-admin batch deletes of readonly-admin/system groups
// fail-closed with "regular group" errors.
func TestTxGroupReadsAndCreate_CarryReadonlyAdminAndSystemFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, _ := txDivergenceFixtures(t, db, ctx)

	// Readonly-admin group written through the DB path.
	roGroup := &rbac.Group{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		Slug:               "twin-ro-" + uuid.New().String()[:8],
		Name:               "Twin Readonly Admin",
		Depth:              0,
		Path:               "twin-ro",
		IsOrgReadonlyAdmin: true,
	}
	if err := db.CreateGroup(ctx, roGroup); err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	// System flag is normally seeded by migrations; set it directly.
	if _, err := db.Conn().ExecContext(ctx,
		`UPDATE groups SET is_system = true WHERE id = $1`, roGroup.ID); err != nil {
		t.Fatalf("failed to set is_system: %v", err)
	}

	// No t.Fatal inside the WithTx callback (see the contract-reads test).
	var byID *rbac.Group
	var byIDs []*rbac.Group
	err := db.WithTx(ctx, func(tx *Tx) error {
		var err error
		if byID, err = tx.GetGroup(ctx, roGroup.ID); err != nil {
			return fmt.Errorf("tx.GetGroup: %w", err)
		}
		if byIDs, err = tx.GetGroupsByIDs(ctx, orgID, []string{roGroup.ID}); err != nil {
			return fmt.Errorf("tx.GetGroupsByIDs: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx failed: %v", err)
	}

	if byID == nil {
		t.Fatal("tx.GetGroup returned nil for existing group")
	}
	if !byID.IsOrgReadonlyAdmin {
		t.Error("tx.GetGroup dropped is_org_readonly_admin")
	}
	if !byID.IsSystem {
		t.Error("tx.GetGroup dropped is_system")
	}

	if len(byIDs) != 1 {
		t.Fatalf("tx.GetGroupsByIDs returned %d groups, want 1", len(byIDs))
	}
	if !byIDs[0].IsOrgReadonlyAdmin {
		t.Error("tx.GetGroupsByIDs dropped is_org_readonly_admin (breaks the RD-1107 batch-delete gate)")
	}
	if !byIDs[0].IsSystem {
		t.Error("tx.GetGroupsByIDs dropped is_system (breaks the RD-1107 batch-delete gate)")
	}

	// Readonly-admin group written through the tx path must persist the flag.
	txGroup := &rbac.Group{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		Slug:               "twin-ro-tx-" + uuid.New().String()[:8],
		Name:               "Twin Readonly Admin via Tx",
		Depth:              0,
		Path:               "twin-ro-tx",
		IsOrgReadonlyAdmin: true,
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.CreateGroup(ctx, txGroup) }); err != nil {
		t.Fatalf("tx.CreateGroup failed: %v", err)
	}
	found, err := db.GetGroup(ctx, txGroup.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if found == nil {
		t.Fatal("group missing after tx create")
	}
	if !found.IsOrgReadonlyAdmin {
		t.Error("is_org_readonly_admin lost through tx create path")
	}
}

// The tx INSERT twin for group_access had dropped verbose_errors (RD-1137).
func TestTxCreateGroupAccess_PersistsVerboseErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	_, groupID := txDivergenceFixtures(t, db, ctx)

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		AllowedMethods: []string{"eth_blockNumber"},
		Claims:         []rbac.Claim{},
		VerboseErrors:  true,
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.CreateGroupAccess(ctx, access) }); err != nil {
		t.Fatalf("tx.CreateGroupAccess failed: %v", err)
	}

	found, err := db.GetGroupAccess(ctx, groupID)
	if err != nil {
		t.Fatalf("GetGroupAccess failed: %v", err)
	}
	if found == nil {
		t.Fatal("group access missing after tx create")
	}
	if !found.VerboseErrors {
		t.Error("verbose_errors lost through tx create path")
	}
}

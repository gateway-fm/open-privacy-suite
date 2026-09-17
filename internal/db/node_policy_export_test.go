package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/nodepolicy"
)

func TestNodePolicyExportPreservesIdentityAndScopedFacts(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	user, org := cacheGenFixtures(t, d, ctx)
	group := uuid.NewString()
	addr := "0x8888888888888888888888888888888888888888"
	sanctioned := "0x9999999999999999999999999999999999999999"
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO groups(id,org_id,slug,name,depth,path) VALUES($1,$2,'payments','Payments',0,'payments')`, group, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO group_access(group_id,claims,allowed_methods) VALUES($1,ARRAY['deploy'],ARRAY['eth_sendRawTransaction'])`, group); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO user_memberships(user_id,group_id,expires_at) VALUES($1,$2,'2030-01-01T00:00:00Z')`, user, group); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO eth_address_links(did,eth_address,link_type) SELECT external_id,$2,'system' FROM users WHERE id=$1`, user, addr); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO sanctioned_addresses(org_id,address,reason) VALUES($1,$2,'private note')`, org, sanctioned); err != nil {
		t.Fatal(err)
	}
	contract := uuid.NewString()
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO contracts(id,org_id,address,name) VALUES($1,$2,$3,'Payments')`, contract, org, addr); err != nil {
		t.Fatal(err)
	}
	// The legacy physical grant claims column is not the current resolver's
	// authority: group_access claims apply only where that group has a grant.
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO contract_grants(group_id,contract_id,claims) VALUES($1,$2,ARRAY['upgrade'])`, group, contract); err != nil {
		t.Fatal(err)
	}
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "export-test"}
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	s, err := d.ExportNodePolicySnapshot(ctx, network, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != uint64(policyVersion(t, d)) {
		t.Fatal("snapshot watermark differs from committed state")
	}
	p, err := nodepolicy.Pin(s)
	if err != nil {
		t.Fatal(err)
	}
	i := nodepolicy.Identity{Header: s.Header, PrincipalID: user, OrgID: org, Signer: addr, MinSnapshotVersion: s.Version}
	facts, err := p.Resolve(i, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts.Groups) != 1 || facts.Groups[0].Claims != nodepolicy.ClaimDeploy {
		t.Fatalf("group facts: %+v", facts)
	}
	grants := facts.Groups[0].ContractClaims
	if len(grants) != 1 || grants[0].Address != addr || grants[0].Claims != nodepolicy.ClaimDeploy {
		t.Fatalf("target claim facts must match current resolver: %+v", grants)
	}
	if !p.IsSanctioned(sanctioned, org) || p.IsSanctioned(sanctioned, "other-org") {
		t.Fatal("sanction scope changed")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "did:test:") || strings.Contains(string(b), "private note") {
		t.Fatal("node export includes identity/operational notes")
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE group_access SET claims='{}' WHERE group_id=$1`, group); err != nil {
		t.Fatal(err)
	}
	revoked, err := d.ExportNodePolicySnapshot(ctx, network, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range revoked.Groups {
		if g.ID == group && (g.Claims != 0 || len(g.ContractClaims) != 1 || g.ContractClaims[0].Claims != 0) {
			t.Fatalf("group claim revocation lost: %+v", g)
		}
	}
}

func TestNodePolicyExportUnlinkAndBan(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	user, _ := cacheGenFixtures(t, d, ctx)
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	s, err := d.ExportNodePolicySnapshot(ctx, nodepolicy.Network{ChainID: 31337, DeploymentID: "export-test"}, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Principals {
		if p.ID == user {
			if !p.Banned || len(p.LinkedAddresses) != 0 {
				t.Fatal("ban/link facts lost")
			}
			return
		}
	}
	t.Fatal("principal absent")
}

func TestNodePolicyExportDeploymentFactsAndPendingConflict(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	user, org := cacheGenFixtures(t, d, ctx)
	address := "0x" + strings.Repeat("ab", 20)
	before := policyVersion(t, d)
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO preregistered_addresses(org_id,address) VALUES($1,$2)`, org, address); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) <= before {
		t.Fatal("pending ownership did not publish a fact change")
	}
	export := func() (nodepolicy.Snapshot, error) {
		return d.ExportNodePolicySnapshot(ctx, nodepolicy.Network{ChainID: 31337, DeploymentID: "export-test"}, time.Now(), time.Minute)
	}
	s, err := export()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Contracts) != 1 || !s.Contracts[0].Pending || s.Contracts[0].OrgID != org || s.Contracts[0].DeployerPrincipalID != "" {
		t.Fatalf("pending facts: %+v", s.Contracts)
	}
	_, otherOrg := cacheGenFixtures(t, d, ctx)
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO preregistered_addresses(org_id,address) VALUES($1,$2)`, otherOrg, "0x"+strings.ToUpper(address[2:])); err != nil {
		t.Fatal(err)
	}
	if _, err := export(); err == nil {
		t.Fatal("ambiguous pending owner was silently selected")
	}
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO contracts(id,org_id,address,name,deployed_by_user_id) VALUES($1,$2,$3,'Actual deployment',$4)`, uuid.NewString(), org, address, user); err != nil {
		t.Fatal(err)
	}
	s, err = export()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Contracts) != 1 || s.Contracts[0].Pending || s.Contracts[0].OrgID != org || s.Contracts[0].DeployerPrincipalID != user {
		t.Fatalf("registered ownership must win: %+v", s.Contracts)
	}
}

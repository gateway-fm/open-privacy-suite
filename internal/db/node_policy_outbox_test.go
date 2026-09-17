package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func policyVersion(t *testing.T, d *DB) int64 {
	t.Helper()
	var v int64
	if err := d.conn.QueryRow(`SELECT version FROM node_policy_clock WHERE singleton`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNodePolicyOutboxAtomicRollbackAndBatch(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	userID, _ := cacheGenFixtures(t, d, ctx)
	before := policyVersion(t, d)
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET kyc=false WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	var inside int64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM node_policy_clock WHERE singleton`).Scan(&inside); err != nil {
		t.Fatal(err)
	}
	if inside != before+1 {
		t.Fatalf("one tx must produce one version: %d -> %d", before, inside)
	}
	if policyVersion(t, d) != before {
		t.Fatal("uncommitted version visible")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) != before {
		t.Fatal("rollback left fact version")
	}
	if err := d.WithTx(ctx, func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, userID); err != nil {
			return err
		}
		_, err := tx.tx.ExecContext(ctx, `UPDATE users SET kyc=false WHERE id=$1`, userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var body []byte
	if err := d.conn.QueryRowContext(ctx, `SELECT changes FROM node_policy_outbox WHERE version=$1`, before+1).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var changes map[string]map[string]bool
	if err := json.Unmarshal(body, &changes); err != nil {
		t.Fatal(err)
	}
	if !changes["principal"][userID] || len(changes["principal"]) != 1 {
		t.Fatalf("wrong coalesced changes: %s", body)
	}
}

func TestNodePolicyOutboxSerializesCommitOrder(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	first, _ := cacheGenFixtures(t, d, ctx)
	second, _ := cacheGenFixtures(t, d, ctx)
	before := policyVersion(t, d)
	a, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Rollback()
	if _, err := a.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, first); err != nil {
		t.Fatal(err)
	}
	b, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Rollback()
	if _, err := b.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, second); err == nil {
		t.Fatal("later transaction could allocate a version before earlier commit")
	}
	if err := b.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) != before+1 {
		t.Fatal("failed concurrent update published a version")
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, second); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) != before+2 {
		t.Fatal("successful retry did not follow prior commit")
	}
}

func TestNodePolicyOutboxLinkUpdatesPrincipal(t *testing.T) {
	d := setupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userID, _ := cacheGenFixtures(t, d, ctx)
	before := policyVersion(t, d)
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO eth_address_links(did,eth_address,link_type) SELECT external_id,'0x7777777777777777777777777777777777777777','system' FROM users WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	var marked bool
	if err := d.conn.QueryRowContext(ctx, `SELECT changes->'principal' ? $1 FROM node_policy_outbox WHERE version=$2`, userID, before+1).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("link changed without principal outbox event")
	}
}

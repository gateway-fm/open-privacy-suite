package db

import (
	"context"
	"privacy-proxy/internal/nodepolicy"
	"strings"
	"testing"
)

func TestNodePolicyAcknowledgementTracksOnlyAppliedCommittedVersions(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	version, err := d.NodePolicyVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ack := nodepolicy.AppliedState{Version: version, Digest: strings.Repeat("a", 64), ExpiresAt: 2000}
	if err := d.AcknowledgeNodePolicy(ctx, "producer", ack); err != nil {
		t.Fatal(err)
	}
	progress, err := d.NodePolicyProgress(ctx, "producer")
	if err != nil || progress.Applied == nil || progress.Applied.Version != version || progress.DesiredVersion != version || progress.Applied.Digest != ack.Digest {
		t.Fatalf("wrong applied progress %+v %v", progress, err)
	}
	// A future acknowledgement must never claim uncommitted authority.
	future := ack
	future.Version++
	if err := d.AcknowledgeNodePolicy(ctx, "producer", future); err == nil {
		t.Fatal("future node acknowledgement accepted")
	}
	if _, err := d.conn.ExecContext(ctx, `SELECT node_policy_mark_dirty('principal','fixture')`); err != nil {
		t.Fatal(err)
	}
	next := ack
	next.Version++
	if err := d.AcknowledgeNodePolicy(ctx, "producer", next); err != nil {
		t.Fatal(err)
	}
	if err := d.AcknowledgeNodePolicy(ctx, "producer", ack); err == nil {
		t.Fatal("late acknowledgement regressed cursor")
	}
	progress, err = d.NodePolicyProgress(ctx, "producer")
	if err != nil || progress.Applied.Version != next.Version {
		t.Fatal("applied cursor regressed")
	}
	missing, err := d.NodePolicyProgress(ctx, "unconnected")
	if err != nil || missing.Applied != nil {
		t.Fatal("unknown node reported applied")
	}
}

package nodepolicy

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func applySigned(t *testing.T, feed *Feed, v Verifier, kind string, payload any) error {
	t.Helper()
	wire, err := testSigner().Seal(kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	return feed.Apply(v, wire)
}

func TestFeedAppliesAtomicRevocationAndPinsPriorGeneration(t *testing.T) {
	f := new(Feed)
	base := snapshotFixture()
	if err := applySigned(t, f, testVerifier(), "snapshot", base); err != nil {
		t.Fatal(err)
	}
	before, err := f.Pin(time.Unix(1020, 0))
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(base)
	next.Version += 3 // A coherent exporter can coalesce committed versions.
	next.Principals[0].Banned = true
	next.Groups = next.Groups[1:]
	next.Principals[0].Memberships = nil
	delta, err := BuildDelta(base, before.Digest(), next)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySigned(t, f, testVerifier(), "delta", delta); err != nil {
		t.Fatal(err)
	}
	if err := applySigned(t, f, testVerifier(), "delta", delta); err != nil {
		t.Fatalf("duplicate retry: %v", err)
	}
	after, err := f.Pin(time.Unix(1020, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.Snapshot(), cloneSnapshot(next)) {
		t.Fatal("delta did not reconstruct final facts")
	}
	if _, err := after.Resolve(identityFixture(), time.Unix(1020, 0)); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("revocation not enforced: %v", err)
	}
	if _, err := before.Resolve(identityFixture(), time.Unix(1020, 0)); err != nil {
		t.Fatalf("pinned candidate mutated: %v", err)
	}
	if before.Digest() == after.Digest() {
		t.Fatal("applied payload digest did not advance")
	}
}

func TestFeedRejectsGapsConflictsAndPartialUpdates(t *testing.T) {
	for _, mutation := range []string{"gap", "digest", "same_version", "regression", "dangling", "duplicate", "delete_overlap", "missing_delete", "wrong_network"} {
		t.Run(mutation, func(t *testing.T) {
			f := new(Feed)
			base := snapshotFixture()
			if err := applySigned(t, f, testVerifier(), "snapshot", base); err != nil {
				t.Fatal(err)
			}
			view, _ := f.Pin(time.Unix(1020, 0))
			next := cloneSnapshot(base)
			next.Version++
			next.Principals[0].Banned = true
			d, err := BuildDelta(base, view.Digest(), next)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "gap":
				d.PreviousVersion--
			case "digest":
				d.PreviousDigest = strings.Repeat("0", 64)
			case "same_version":
				d.Version = base.Version
			case "regression":
				d.Version = base.Version - 1
			case "dangling":
				d.Deletes.Groups = []string{"payments"}
			case "duplicate":
				d.Upserts.Principals = append(d.Upserts.Principals, d.Upserts.Principals[0])
			case "delete_overlap":
				d.Deletes.Principals = []string{"user-a"}
			case "missing_delete":
				d.Deletes.Principals = []string{"unknown"}
			case "wrong_network":
				d.Network.DeploymentID = "elsewhere"
			}
			if err := applySigned(t, f, testVerifier(), "delta", d); err == nil {
				t.Fatal("invalid delta accepted")
			}
			got, err := f.Pin(time.Unix(1020, 0))
			if err != nil || got.Digest() != view.Digest() || !reflect.DeepEqual(got.Snapshot(), view.Snapshot()) {
				t.Fatal("failed delta partially published")
			}
		})
	}
}

func TestHeartbeatRefreshesLeaseWithoutRewritingFacts(t *testing.T) {
	f := new(Feed)
	base := snapshotFixture()
	if err := applySigned(t, f, testVerifier(), "snapshot", base); err != nil {
		t.Fatal(err)
	}
	before, _ := f.Pin(time.Unix(1020, 0))
	lease := Header{Network: base.Network, IssuedAt: 1090, ExpiresAt: 1190}
	hb := Heartbeat{Header: lease, Version: base.Version, Digest: before.Digest()}
	v := testVerifier()
	v.Now = func() time.Time { return time.Unix(1090, 0) }
	if err := applySigned(t, f, v, "heartbeat", hb); err != nil {
		t.Fatal(err)
	}
	after, err := f.Pin(time.Unix(1110, 0))
	if err != nil {
		t.Fatal(err)
	}
	i := identityFixture()
	i.PrincipalID = "user-b" // This membership does not expire at 1050.
	i.Header = lease
	if _, err := after.Resolve(i, time.Unix(1110, 0)); err != nil {
		t.Fatalf("fresh lease ignored: %v", err)
	}
	if !reflect.DeepEqual(after.Snapshot(), before.Snapshot()) || after.Digest() != before.Digest() {
		t.Fatal("heartbeat changed immutable facts")
	}
	if _, err := before.Resolve(i, time.Unix(1110, 0)); !errors.Is(err, ErrExpired) {
		t.Fatal("earlier pinned lease was mutated")
	}
	if _, err := f.Pin(time.Unix(1190, 0)); !errors.Is(err, ErrExpired) {
		t.Fatal("stale feed still ready")
	}
	for _, what := range []string{"version", "digest", "lease_regression"} {
		bad := hb
		switch what {
		case "version":
			bad.Version++
		case "digest":
			bad.Digest = strings.Repeat("0", 64)
		case "lease_regression":
			bad.ExpiresAt--
		}
		if err := applySigned(t, f, v, "heartbeat", bad); err == nil {
			t.Fatalf("accepted heartbeat %s", what)
		}
	}
}

func TestFeedRejectsSameVersionSnapshotRewriteAndUnsignedMessages(t *testing.T) {
	f := new(Feed)
	base := snapshotFixture()
	if err := applySigned(t, f, testVerifier(), "snapshot", base); err != nil {
		t.Fatal(err)
	}
	base.ExpiresAt++ // Even header changes would change the payload digest.
	if err := applySigned(t, f, testVerifier(), "snapshot", base); err == nil {
		t.Fatal("rewrote installed version")
	}
	raw, _ := json.Marshal(base)
	if err := f.Apply(testVerifier(), raw); err == nil {
		t.Fatal("accepted unsigned facts")
	}
	base.Version++
	if err := applySigned(t, f, testVerifier(), "snapshot", base); err != nil {
		t.Fatalf("new full resync rejected: %v", err)
	}
}

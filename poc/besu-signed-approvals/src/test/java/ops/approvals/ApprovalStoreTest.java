package ops.approvals;

import static ops.approvals.Fixtures.approval;
import static ops.approvals.Fixtures.hash;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/** Wire contract §3 (which approval is kept) and §6 (how long, and what goes first under pressure). */
class ApprovalStoreTest {
  private static final long GRACE = 5_000;
  private static final long TTL = 600_000;

  private final AtomicLong clock = new AtomicLong(1_800_000_000_000L);

  private ApprovalStore store(final int capacity) {
    return new ApprovalStore(capacity, GRACE, clock::get);
  }

  private boolean put(final ApprovalStore store, final Approval a, final String keyId, final long issuedAt) {
    return store.putAll(keyId, issuedAt, issuedAt + TTL, List.of(a));
  }

  private boolean put(final ApprovalStore store, final Approval a, final long issuedAt) {
    return put(store, a, "default", issuedAt);
  }

  private static Hash fingerprint(final ApprovalStore store, final int tx) {
    return store.get(hash(tx)).orElseThrow().approval().fingerprint();
  }

  @Test
  void keepsTheGreatestIssuedAtThenKeyIdThenFingerprint() {
    final ApprovalStore store = store(10);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 5), t));
    assertTrue(put(store, approval(1, 9), t - 1), "an earlier issued_at changes nothing, and is still OK");
    assertEquals(hash(5), fingerprint(store, 1));
    assertTrue(put(store, approval(1, 4), t), "same issued_at and key id, smaller fingerprint");
    assertEquals(hash(5), fingerprint(store, 1));
    assertTrue(put(store, approval(1, 6), t), "same issued_at and key id, greater fingerprint");
    assertEquals(hash(6), fingerprint(store, 1));
    assertTrue(put(store, approval(1, 1), "next", t), "same issued_at, key id 'next' > 'default' bytewise");
    assertEquals(hash(1), fingerprint(store, 1));
    assertTrue(put(store, approval(1, 2), "default", t + 1), "a later issued_at wins");
    assertEquals(hash(2), fingerprint(store, 1));
    final ApprovalStore.Stored kept = store.get(hash(1)).orElseThrow();
    assertTrue(put(store, approval(1, 2), "default", t + 1), "re-delivering the stored approval is a no-op");
    assertEquals(kept, store.get(hash(1)).orElseThrow());
    assertEquals(1, store.size());
  }

  @Test
  void aPrimaryAndAStandbyKeepTheSameApprovalWhateverTheArrivalOrder() {
    final long t = clock.get();
    final List<Object[]> deliveries = new ArrayList<>();
    deliveries.add(new Object[] {approval(1, 3), "default", t});
    deliveries.add(new Object[] {approval(1, 8), "default", t});
    deliveries.add(new Object[] {approval(1, 2), "a", t});
    deliveries.add(new Object[] {approval(1, 1), "default", t - 5});
    for (int round = 0; round < 8; round++) {
      final ApprovalStore primary = store(10);
      final ApprovalStore standby = store(10);
      final List<Object[]> reversed = new ArrayList<>(deliveries);
      Collections.reverse(reversed);
      if (round > 0) {
        Collections.shuffle(reversed, new java.util.Random(round));
      }
      deliveries.forEach(d -> put(primary, (Approval) d[0], (String) d[1], (Long) d[2]));
      reversed.forEach(d -> put(standby, (Approval) d[0], (String) d[1], (Long) d[2]));
      assertEquals(hash(8), fingerprint(primary, 1));
      assertEquals(primary.get(hash(1)), standby.get(hash(1)), "round " + round);
    }
  }

  @Test
  void anExpiredApprovalCountsAsAbsentAndIsReplacedWhateverItsRank() {
    final ApprovalStore store = store(10);
    final long t = clock.get();
    assertTrue(store.putAll("default", t, t + 1_000, List.of(approval(1, 5))));
    clock.addAndGet(1_000); // now = expires_at: no longer usable
    assertFalse(store.get(hash(1)).orElseThrow().usableAt(clock.get()));
    assertTrue(store.putAll("default", t - 10, t + TTL, List.of(approval(1, 6))), "an older approval that is still valid");
    assertEquals(hash(6), fingerprint(store, 1));
    assertTrue(store.get(hash(1)).orElseThrow().usableAt(clock.get()));
  }

  @Test
  void theStoreEvictsExpiredApprovals() {
    final ApprovalStore store = store(10);
    final long t = clock.get();
    store.putAll("default", t, t + 1_000, List.of(approval(1, 1)));
    store.putAll("default", t, t + 2_000, List.of(approval(2, 2)));
    store.pooled(hash(1)); // pooled or not, an expired approval is unusable
    clock.addAndGet(999);
    assertEquals(0, store.evictExpired());
    clock.addAndGet(1);
    assertEquals(1, store.evictExpired());
    assertTrue(store.get(hash(1)).isEmpty());
    assertTrue(store.get(hash(2)).isPresent());
    clock.addAndGet(1_000);
    assertEquals(1, store.evictExpired());
    assertEquals(0, store.size());
  }

  @Test
  void aBatchIsAllOrNothingAndRoomIsCountedBeforeAnythingIsEvicted() {
    final ApprovalStore store = store(2);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 1), t - 60_000)); // an old orphan: evictable
    assertTrue(put(store, approval(2, 2), t - 60_000));
    store.pooled(hash(2)); // live: never evicted
    // Two new approvals need two slots; one could be made. Refuse, and evict nothing for it.
    assertFalse(store.putAll("default", t, t + TTL, List.of(approval(3, 3), approval(4, 4))));
    assertTrue(store.get(hash(1)).isPresent(), "a refused batch must not have evicted anything");
    assertTrue(store.get(hash(3)).isEmpty());
    assertTrue(store.get(hash(4)).isEmpty());
    // One new approval fits once the orphan goes.
    assertTrue(store.putAll("default", t, t + TTL, List.of(approval(3, 3))));
    assertTrue(store.get(hash(1)).isEmpty());
    assertEquals(2, store.size());
  }

  @Test
  void replacementsNeedNoRoom() {
    final ApprovalStore store = store(1);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 1), t));
    store.pooled(hash(1));
    assertTrue(put(store, approval(1, 2), t + 1), "a full store still takes a newer approval for a held transaction");
    assertEquals(hash(2), fingerprint(store, 1));
    assertTrue(put(store, approval(1, 2), t + 1), "and a redelivery");
  }

  @Test
  void underPressureExpiredGoFirstThenIncludedThenTheOldestOrphans() {
    final ApprovalStore store = store(4);
    final long t = clock.get();
    store.putAll("default", t - 40_000, t - 40_000 + TTL, List.of(approval(1, 1))); // orphan, oldest
    store.putAll("default", t - 30_000, t - 30_000 + TTL, List.of(approval(2, 2))); // orphan
    store.putAll("default", t - 20_000, t - 20_000 + TTL, List.of(approval(3, 3))); // included
    store.putAll("default", t - 10_000, t + 1, List.of(approval(4, 4))); // expires soon, pooled
    store.included(hash(3));
    store.pooled(hash(4));
    clock.addAndGet(1); // approval 4 has expired

    assertTrue(put(store, approval(10, 10), t));
    assertTrue(store.get(hash(4)).isEmpty(), "the expired approval goes first, pooled or not");
    assertTrue(put(store, approval(11, 11), t));
    assertTrue(store.get(hash(3)).isEmpty(), "then the included one, although younger than the orphans");
    assertTrue(put(store, approval(12, 12), t));
    assertTrue(store.get(hash(1)).isEmpty(), "then the oldest orphan");
    assertTrue(store.get(hash(2)).isPresent());
  }

  @Test
  void theOldestOrphanIsTheEarliestIssuedNotTheEarliestArrived() {
    final ApprovalStore store = store(2);
    final long t = clock.get();
    // A redelivery after a restart arrives newest first.
    store.putAll("default", t - 10_000, t - 10_000 + TTL, List.of(approval(1, 1)));
    store.putAll("default", t - 50_000, t - 50_000 + TTL, List.of(approval(2, 2)));
    assertTrue(put(store, approval(3, 3), t));
    assertTrue(store.get(hash(2)).isEmpty(), "issued earlier, arrived later: it goes first");
    assertTrue(store.get(hash(1)).isPresent());
  }

  @Test
  void youthIsMeasuredFromIssuedAtSoAReplayCannotMakeAnOldApprovalYoung() {
    final ApprovalStore store = store(1);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 1), t - 1_000)); // issued 1 s ago: young
    assertFalse(put(store, approval(2, 2), t), "a young approval is never evicted for a new one");
    clock.addAndGet(GRACE);
    assertTrue(put(store, approval(2, 2), t), "5 s later it is no longer young");
    // An old approval arriving now (a replayed or redelivered batch) is old from the start.
    final ApprovalStore other = store(1);
    assertTrue(put(other, approval(1, 1), clock.get() - GRACE));
    assertTrue(put(other, approval(2, 2), clock.get()), "arrival does not make it young");
    assertTrue(other.get(hash(1)).isEmpty());
  }

  @Test
  void approvalsOfPooledTransactionsAreNeverEvicted() {
    final ApprovalStore store = store(1);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 1), t - 60_000));
    store.pooled(hash(1));
    assertFalse(put(store, approval(2, 2), t));
    store.unpooled(hash(1)); // dropped from the pool: an orphan now
    assertTrue(put(store, approval(2, 2), t));
    assertTrue(store.get(hash(1)).isEmpty());
  }

  @Test
  void pooledTransactionsStillWaitingForAnApprovalTakeNoCapacity() {
    final ApprovalStore store = store(1);
    for (int i = 100; i < 1_100; i++) {
      store.pooled(hash(i));
    }
    // A thousand pooled transactions and a store of one: the first approval still fits.
    assertTrue(put(store, approval(100, 1), clock.get() - 60_000));
    assertEquals(1, store.size());
    // It arrived after its transaction, so it is live at once, old as it is: nothing can go.
    assertFalse(put(store, approval(2, 2), clock.get()));
  }

  @Test
  void aReorganisedTransactionIsLiveAgain() {
    final ApprovalStore store = store(1);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 1), t - 60_000));
    store.pooled(hash(1));
    store.included(hash(1));
    store.pooled(hash(1)); // the block was reorganised away and the transaction is back
    assertFalse(put(store, approval(2, 2), t), "live again: not evictable");
    store.included(hash(1));
    assertTrue(put(store, approval(2, 2), t), "included again: evictable before orphans");
  }

  @Test
  void finalityReleasesApprovals() {
    final ApprovalStore store = store(10);
    put(store, approval(1, 1), clock.get());
    put(store, approval(2, 2), clock.get());
    store.removeAll(List.of(hash(1)));
    assertTrue(store.get(hash(1)).isEmpty());
    assertTrue(store.get(hash(2)).isPresent());
  }

  @Test
  void reconcilingWithThePoolNeverUnpoolsATransactionAddedAfterTheSnapshot() {
    final ApprovalStore store = store(1);
    final long t = clock.get();
    assertTrue(put(store, approval(1, 1), t - 60_000));
    final long snapshotTakenAt = clock.get();
    clock.addAndGet(10);
    store.pooled(hash(1)); // arrives while the snapshot (which lacks it) is in flight
    store.reconcile(Set.of(), snapshotTakenAt);
    assertFalse(put(store, approval(2, 2), t), "still live");
    // A snapshot taken after that without it means it really left the pool.
    clock.addAndGet(1);
    store.reconcile(Set.of(), clock.get());
    assertTrue(put(store, approval(2, 2), t));
    // And a pooled transaction the events missed is found.
    final ApprovalStore missed = store(1);
    assertTrue(put(missed, approval(3, 3), t - 60_000));
    missed.reconcile(Set.of(hash(3)), clock.get());
    assertFalse(put(missed, approval(4, 4), t), "the snapshot made it live");
  }
}

package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicLong;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/**
 * A full store is the normal state under load once approvals are kept until finality. Every
 * further approval must then cost about as much as an ordinary one — no scan of the transaction
 * pool, no sort of every held approval — and it must never evict an approval whose transaction is
 * live in the pool, nor one so young that its transaction may not have arrived yet.
 */
class ApprovalStoreOverflowTest {
  private static Approval approval(final int tx) {
    return new Approval(
        Approval.HASH_CALLS, 31337, Hash.wrap(Bytes32.leftPad(Bytes.of((byte) (tx >> 8), (byte) tx))), Hash.ZERO, Hash.ZERO);
  }

  @Test
  void overflowEvictsTheOldestUnpooledApprovalWithoutTouchingThePool() {
    final AtomicLong clock = new AtomicLong(1_000);
    final ApprovalStore store = new ApprovalStore(1_000, 60_000, 5_000, clock::get);
    for (int i = 0; i < 1_000; i++) {
      assertTrue(store.put(approval(i)));
    }
    clock.addAndGet(6_000); // older than the grace period: evictable if unpooled
    for (int i = 1_000; i < 2_000; i++) {
      assertTrue(store.put(approval(i)), "approval " + i + " refused although unpooled ones can go");
    }
    assertEquals(1_000, store.size());
    assertTrue(store.get(approval(0).txHash()).isEmpty());
    assertTrue(store.get(approval(1_999).txHash()).isPresent());
  }

  @Test
  void liveAndYoungApprovalsAreNeverEvicted() {
    final AtomicLong clock = new AtomicLong(1_000);
    final ApprovalStore store = new ApprovalStore(2, 60_000, 5_000, clock::get);
    assertTrue(store.put(approval(1)));
    assertTrue(store.put(approval(2)));
    store.pooled(approval(1).txHash()); // its transaction arrived: live
    clock.addAndGet(10_000); // both are old now, but 1 is live and 2 is not
    assertTrue(store.put(approval(3)), "the old, unpooled approval 2 should make room");
    assertTrue(store.get(approval(1).txHash()).isPresent());
    assertTrue(store.get(approval(2).txHash()).isEmpty());
    // 1 is live, 3 is young: nothing may be evicted for 4.
    assertFalse(store.put(approval(4)), "a full store of live or young approvals must refuse");
    store.unpooled(approval(1).txHash()); // included or dropped: no longer live
    assertTrue(store.put(approval(4)), "once 1 is unpooled and old, it can go");
    assertTrue(store.get(approval(1).txHash()).isEmpty());
  }
}

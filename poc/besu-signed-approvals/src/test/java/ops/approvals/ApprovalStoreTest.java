package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

class ApprovalStoreTest {
  private static Approval approval(final int tx, final int fingerprint) {
    return new Approval(
        Approval.HASH_CALLS,
        31337,
        Hash.wrap(Bytes32.leftPad(org.apache.tuweni.bytes.Bytes.of(tx))),
        Hash.wrap(Bytes32.leftPad(org.apache.tuweni.bytes.Bytes.of(fingerprint))),
        Hash.ZERO);
  }

  @Test
  void storesLatestApprovalPerTransactionAndRespectsCapacity() {
    final AtomicLong clock = new AtomicLong(1_000);
    final ApprovalStore store = new ApprovalStore(2, 60_000, 5_000, clock::get);
    assertTrue(store.put(approval(1, 1)));
    assertTrue(store.put(approval(1, 1))); // duplicate is idempotent, not a second slot
    assertTrue(store.put(approval(1, 2))); // a newer preflight for the same tx replaces
    assertEquals(approval(1, 2), store.get(approval(1, 0).txHash()).orElseThrow());
    assertTrue(store.put(approval(2, 1)));
    store.pooled(approval(1, 0).txHash());
    store.pooled(approval(2, 0).txHash());
    clock.addAndGet(10_000);
    assertFalse(store.put(approval(3, 1))); // full of live approvals: refuse, never approve implicitly
    assertEquals(2, store.size());
    assertTrue(store.get(approval(3, 0).txHash()).isEmpty());
  }

  @Test
  void fullStoreGivesUpOldUnpooledApprovalsBeforeRefusing() {
    final AtomicLong clock = new AtomicLong(1_000);
    final ApprovalStore store = new ApprovalStore(2, 60_000, 5_000, clock::get);
    store.put(approval(1, 1));
    clock.incrementAndGet();
    store.put(approval(2, 1));
    store.pooled(approval(2, 0).txHash());
    assertFalse(store.put(approval(3, 1)), "approval 1 is unpooled but too young to give up");
    clock.addAndGet(10_000);
    assertTrue(store.put(approval(3, 1)), "oldest unpooled approval (1) makes room once old enough");
    assertTrue(store.get(approval(1, 0).txHash()).isEmpty());
    store.pooled(approval(3, 0).txHash());
    clock.addAndGet(10_000);
    assertFalse(store.put(approval(4, 1)), "every held approval backs a pooled transaction: refuse");
    assertEquals(2, store.size());
  }

  @Test
  void removesIncludedAndSweepsOrphansByTtl() {
    final AtomicLong clock = new AtomicLong(1_000);
    final ApprovalStore store = new ApprovalStore(100, 5_000, 0, clock::get);
    store.put(approval(1, 1));
    store.put(approval(2, 1));
    store.removeAll(List.of(approval(1, 0).txHash()));
    assertTrue(store.get(approval(1, 0).txHash()).isEmpty());
    clock.set(5_999);
    assertEquals(0, store.sweepOrphans(Set.of()));
    clock.set(6_000);
    // Approval 2 is still referenced by a pool transaction: it must survive the sweep.
    assertEquals(0, store.sweepOrphans(Set.of(approval(2, 0).txHash())));
    assertEquals(1, store.sweepOrphans(Set.of()));
    assertEquals(0, store.size());
  }
}

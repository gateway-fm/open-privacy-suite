package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * A full store is the normal state under load: every further approval must then cost about as
 * much as an ordinary one — no scan of the transaction pool, no sort of every held approval, no
 * walk past the approvals that cannot go.
 */
class ApprovalStoreOverflowTest {
  private static final long TTL = 600_000;

  @Test
  void aFullStoreEvictsInLogarithmicTimeWithoutTouchingThePool() {
    final AtomicLong clock = new AtomicLong(1_800_000_000_000L);
    final int capacity = 20_000;
    final ApprovalStore store = new ApprovalStore(capacity, 5_000, clock::get);
    final long issued = clock.get() - 60_000;
    // Half live, half orphans, interleaved: a scan from the front would walk past the live ones.
    for (int i = 0; i < capacity; i++) {
      assertTrue(store.putAll("default", issued, issued + TTL, List.of(Fixtures.approval(i, i))));
      if (i % 2 == 0) {
        store.pooled(Fixtures.hash(i));
      }
    }
    final long started = System.nanoTime();
    for (int i = capacity; i < capacity + capacity / 2; i++) {
      assertTrue(store.putAll("default", clock.get(), clock.get() + TTL, List.of(Fixtures.approval(i, i))), "approval " + i);
    }
    final long perPut = (System.nanoTime() - started) / (capacity / 2);
    assertEquals(capacity, store.size());
    for (int i = 0; i < capacity; i += 2) {
      assertTrue(store.get(Fixtures.hash(i)).isPresent(), "live approval " + i + " evicted");
    }
    for (int i = 1; i < capacity; i += 2) {
      assertTrue(store.get(Fixtures.hash(i)).isEmpty(), "orphan " + i + " kept");
    }
    // Generous bound for a slow CI machine; a front-to-back scan costs milliseconds here.
    assertTrue(perPut < 200_000, "overflow put took " + perPut + " ns");
  }
}

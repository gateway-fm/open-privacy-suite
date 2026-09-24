package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * Random operation sequences against the store's contract (wire contract §3, §6): the capacity
 * holds, a refused batch changes nothing, an accepted one leaves every approval that must not be
 * evicted in place and keeps the greatest approval per transaction, and the expiry pass removes
 * exactly the expired ones. The store's eviction indexes must never drift from its states.
 */
class ApprovalStoreInvariantTest {
  private static final int TXS = 40;
  private static final int CAPACITY = 12;
  private static final long GRACE = 5_000;

  private final AtomicLong clock = new AtomicLong(1_800_000_000_000L);

  private Map<Integer, Optional<ApprovalStore.Stored>> snapshot(final ApprovalStore store) {
    final Map<Integer, Optional<ApprovalStore.Stored>> out = new HashMap<>();
    for (int tx = 0; tx < TXS; tx++) {
      out.put(tx, store.get(Fixtures.hash(tx)));
    }
    return out;
  }

  @Test
  void randomOperationsNeverBreakTheStoreContract() {
    for (long seed = 1; seed <= 40; seed++) {
      run(new Random(seed), seed);
    }
  }

  private void run(final Random random, final long seed) {
    final ApprovalStore store = new ApprovalStore(CAPACITY, GRACE, clock::get);
    final Set<Integer> pooled = new HashSet<>();
    for (int step = 0; step < 2_000; step++) {
      final String where = "seed " + seed + " step " + step;
      final long now = clock.get();
      final int tx = random.nextInt(TXS);
      switch (random.nextInt(8)) {
        case 0, 1, 2 -> {
          final Map<Integer, Optional<ApprovalStore.Stored>> before = snapshot(store);
          final long issuedAt = now - random.nextInt(20_000) + 2_000;
          final long expiresAt = issuedAt + 1 + random.nextInt(30_000);
          final String keyId = random.nextBoolean() ? "a" : "b";
          final List<Approval> batch = new ArrayList<>();
          final int n = 1 + random.nextInt(3);
          for (int i = 0; i < n; i++) {
            batch.add(Fixtures.approval(random.nextInt(TXS), random.nextInt(4)));
          }
          final boolean stored = store.putAll(keyId, issuedAt, expiresAt, batch);
          final Map<Integer, Optional<ApprovalStore.Stored>> after = snapshot(store);
          if (!stored) {
            assertEquals(before, after, where + ": a refused batch changed the store");
            break;
          }
          final Set<Integer> offered = new HashSet<>();
          for (final Approval a : batch) {
            final int t = Integer.parseInt(a.txHash().toHexString().substring(2), 16);
            offered.add(t);
            final ApprovalStore.Stored held = after.get(t).orElseThrow(() -> new AssertionError(where + ": offered approval missing"));
            final ApprovalStore.Stored mine = new ApprovalStore.Stored(a, keyId, issuedAt, expiresAt);
            assertTrue(ApprovalStore.rank(held, mine) >= 0, where + ": a lower-ranked approval replaced a greater one");
          }
          for (int t = 0; t < TXS; t++) {
            final Optional<ApprovalStore.Stored> was = before.get(t);
            if (was.isEmpty() || offered.contains(t) || !was.get().usableAt(now)) {
              continue;
            }
            final boolean young = now - was.get().issuedAt() < GRACE;
            if (pooled.contains(t) || young) {
              assertEquals(was, after.get(t), where + ": evicted a " + (young ? "young" : "pooled") + " approval for " + t);
            }
          }
        }
        case 3 -> {
          store.pooled(Fixtures.hash(tx));
          pooled.add(tx);
        }
        case 4 -> {
          store.unpooled(Fixtures.hash(tx));
          pooled.remove(tx);
        }
        case 5 -> {
          store.included(Fixtures.hash(tx));
          pooled.remove(tx);
        }
        case 6 -> {
          final Map<Integer, Optional<ApprovalStore.Stored>> before = snapshot(store);
          final int evicted = store.evictExpired();
          int expected = 0;
          for (int t = 0; t < TXS; t++) {
            final Optional<ApprovalStore.Stored> was = before.get(t);
            final boolean expired = was.isPresent() && !was.get().usableAt(now);
            expected += expired ? 1 : 0;
            assertEquals(expired ? Optional.empty() : was, store.get(Fixtures.hash(t)), where + ": expiry pass for " + t);
          }
          assertEquals(expected, evicted, where);
        }
        default -> clock.addAndGet(random.nextInt(3_000));
      }
      assertTrue(store.size() <= CAPACITY, where + ": over capacity");
      assertEquals(snapshot(store).values().stream().filter(Optional::isPresent).count(), store.size(), where + ": size drift");
    }
  }
}

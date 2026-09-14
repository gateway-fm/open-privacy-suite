package ops.approvals;

import java.util.Collection;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Verified approvals held only in memory, keyed by transaction hash. A newer approval for the same
 * transaction replaces the older one (a re-prepared submission). Capacity overflow refuses new
 * approvals; it never lets a transaction through.
 */
public final class ApprovalStore {
  private record Entry(Approval approval, long storedAt) {}

  private final ConcurrentHashMap<Hash, Entry> entries = new ConcurrentHashMap<>();
  private final int capacity;
  private final long orphanTtlMs;
  private final LongSupplier clock;
  private final Supplier<Set<Hash>> pooled;

  public ApprovalStore(final int capacity, final long orphanTtlMs, final LongSupplier clock) {
    this(capacity, orphanTtlMs, clock, Set::of);
  }

  /** @param pooled transaction hashes currently in the pool, consulted only when the store is full */
  public ApprovalStore(
      final int capacity,
      final long orphanTtlMs,
      final LongSupplier clock,
      final Supplier<Set<Hash>> pooled) {
    this.capacity = capacity;
    this.orphanTtlMs = orphanTtlMs;
    this.clock = clock;
    this.pooled = pooled;
  }

  /** @return false when the store is full of approvals for pooled transactions and this one was not retained */
  public synchronized boolean put(final Approval approval) {
    final Entry entry = new Entry(approval, clock.getAsLong());
    if (entries.containsKey(approval.txHash())) {
      entries.put(approval.txHash(), entry);
      return true;
    }
    if (entries.size() >= capacity) {
      // Approvals whose transaction is not (or no longer) in the pool are the only ones that can
      // be given up without breaking a live submission; drop them oldest first.
      final Set<Hash> referenced = pooled.get();
      entries.entrySet().stream()
          .filter(e -> !referenced.contains(e.getKey()))
          .sorted(Comparator.comparingLong(e -> e.getValue().storedAt()))
          .limit(1)
          .map(Map.Entry::getKey)
          .toList()
          .forEach(entries::remove);
      if (entries.size() >= capacity) {
        return false;
      }
    }
    entries.put(approval.txHash(), entry);
    return true;
  }

  public Optional<Approval> get(final Hash txHash) {
    final Entry e = entries.get(txHash);
    return e == null ? Optional.empty() : Optional.of(e.approval());
  }

  public synchronized void removeAll(final Collection<Hash> txHashes) {
    txHashes.forEach(entries::remove);
  }

  /**
   * Drops approvals older than the TTL whose transaction is not referenced by the pool. Memory
   * hygiene only: dropping never grants anything.
   */
  public synchronized int sweepOrphans(final Set<Hash> referencedTxHashes) {
    final long cutoff = clock.getAsLong() - orphanTtlMs;
    final int before = entries.size();
    entries
        .entrySet()
        .removeIf(e -> e.getValue().storedAt() <= cutoff && !referencedTxHashes.contains(e.getKey()));
    return before - entries.size();
  }

  public int size() {
    return entries.size();
  }
}

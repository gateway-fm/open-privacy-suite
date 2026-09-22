package ops.approvals;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Verified approvals held only in memory, keyed by transaction hash. A newer approval for the same
 * transaction replaces the older one (a re-prepared submission). Capacity overflow refuses new
 * approvals; it never lets a transaction through.
 *
 * <p>Approvals are kept until their block is final, so under load the store is usually full and
 * overflow is the ordinary path. It must cost about as much as an ordinary insert: entries keep
 * insertion order and, on overflow, the oldest approval that is neither <em>live</em> (its
 * transaction is in the pool, learned from the pool's own events through {@link #pooled} and
 * {@link #unpooled}) nor <em>young</em> (younger than the grace period, so its transaction may
 * still be on its way) is dropped — a scan from the front that stops at the first candidate. No
 * pool query and no sort happen on this path; refusing is the fail-closed outcome when nothing
 * can go.
 */
public final class ApprovalStore {
  private record Entry(Approval approval, long storedAt) {}

  private final LinkedHashMap<Hash, Entry> entries = new LinkedHashMap<>();
  private final Set<Hash> live = new HashSet<>();
  private final int capacity;
  private final long orphanTtlMs;
  private final long graceMs;
  private final LongSupplier clock;

  /**
   * @param capacity approvals held at most
   * @param orphanTtlMs age after which an approval with no pooled transaction is swept
   * @param graceMs age below which an approval is never evicted on overflow: its transaction may
   *     not have reached the pool yet (approvals normally arrive first)
   */
  public ApprovalStore(final int capacity, final long orphanTtlMs, final long graceMs, final LongSupplier clock) {
    this.capacity = capacity;
    this.orphanTtlMs = orphanTtlMs;
    this.graceMs = graceMs;
    this.clock = clock;
  }

  /** @return false when the store is full of live or young approvals and this one was not retained */
  public synchronized boolean put(final Approval approval) {
    final long now = clock.getAsLong();
    final Entry entry = new Entry(approval, now);
    if (entries.containsKey(approval.txHash())) {
      entries.put(approval.txHash(), entry); // replaces in place; keeps the original position
      return true;
    }
    if (entries.size() >= capacity && !evictOne(now)) {
      return false;
    }
    entries.put(approval.txHash(), entry);
    return true;
  }

  /** The pool admitted this transaction: its approval is live until {@link #unpooled}. */
  public synchronized void pooled(final Hash txHash) {
    live.add(txHash);
  }

  /** The pool no longer holds this transaction (included, dropped, replaced). */
  public synchronized void unpooled(final Hash txHash) {
    live.remove(txHash);
  }

  private boolean evictOne(final long now) {
    final Iterator<Map.Entry<Hash, Entry>> it = entries.entrySet().iterator();
    while (it.hasNext()) {
      final Map.Entry<Hash, Entry> e = it.next();
      if (!live.contains(e.getKey()) && now - e.getValue().storedAt() >= graceMs) {
        it.remove();
        return true;
      }
    }
    return false;
  }

  public Optional<Approval> get(final Hash txHash) {
    final Entry e;
    synchronized (this) {
      e = entries.get(txHash);
    }
    return e == null ? Optional.empty() : Optional.of(e.approval());
  }

  public synchronized void removeAll(final Collection<Hash> txHashes) {
    for (final Hash h : txHashes) {
      entries.remove(h);
      live.remove(h);
    }
  }

  /**
   * Drops approvals older than the TTL whose transaction is not referenced by the pool, and
   * reconciles the live set with the pool's actual contents. Memory hygiene only: dropping never
   * grants anything.
   */
  public synchronized int sweepOrphans(final Set<Hash> referencedTxHashes) {
    final long cutoff = clock.getAsLong() - orphanTtlMs;
    final int before = entries.size();
    entries
        .entrySet()
        .removeIf(e -> e.getValue().storedAt() <= cutoff && !referencedTxHashes.contains(e.getKey()));
    live.retainAll(referencedTxHashes);
    live.addAll(referencedTxHashes);
    live.retainAll(entries.keySet());
    return before - entries.size();
  }

  public synchronized int size() {
    return entries.size();
  }
}

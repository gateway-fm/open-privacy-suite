package ops.approvals;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.LongSupplier;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Verified approvals held only in memory, keyed by transaction hash (wire contract §3 and §6).
 * Refusing is the only outcome of a full store; it never lets a transaction through.
 *
 * <p><b>Which approval is kept.</b> Per transaction the one with the greatest (issued_at, key id,
 * fingerprint), compared unsigned and then bytewise, so a primary and a standby producer keep the
 * same approval whatever order batches reach them in. An expired approval counts as absent: any
 * valid one replaces it.
 *
 * <p><b>How long.</b> Until its {@code expires_at}, or until the block that included its transaction
 * is final, whichever comes first. The two meet in the three states an approval can be in, which
 * follow the transaction:
 *
 * <ul>
 *   <li><em>pooled</em> — the transaction is in the pool, waiting to be selected. Never evicted:
 *       the producer is about to need it.
 *   <li><em>included</em> — a canonical block holds the transaction. It is kept for a
 *       reorganisation, which returns the transaction to the pool (pooled again, and it must still
 *       find its approval), until the block is final ({@link #removeAll}) — but no longer than its
 *       expiry. Finality can lag the head by hours; expiry is what bounds the store then, and a
 *       reorganisation after expiry needs a fresh preflight.
 *   <li><em>orphan</em> — no pooled or included transaction: it has not arrived yet (an approval
 *       normally precedes its transaction), or it was dropped. Expiry replaces the separate orphan
 *       lifetime; a late approval for a dropped transaction is stored like any other, since the
 *       transaction may be re-announced.
 * </ul>
 *
 * <p><b>Under pressure</b> a new approval may evict, in this order: expired approvals, soonest
 * expired first; approvals of included transactions; orphans; each of the last two oldest first by
 * {@code issued_at}. An approval younger than the grace period, measured from {@code issued_at} and
 * not from arrival, is never evicted for a new one: its transaction may still be on its way, and a
 * redelivered or replayed batch cannot make old approvals young again. The room a batch needs is
 * counted before anything is evicted, so a refused batch evicts nothing. Every step is an ordered
 * index lookup — no pool query, no scan past approvals that cannot go, no sort — because under load
 * a full store is the ordinary state. Pooled transactions still waiting for an approval are tracked
 * without taking capacity.
 */
public final class ApprovalStore {
  /** An approval as stored, with what the replacement rule and expiry need from its batch. */
  public record Stored(Approval approval, String keyId, long issuedAt, long expiresAt) {
    /** Usable while now &lt; expires_at; no grace period (wire contract §6). */
    public boolean usableAt(final long now) {
      return now < expiresAt;
    }
  }

  private enum State {
    POOLED,
    INCLUDED,
    ORPHAN
  }

  private static final class Entry {
    Stored stored;
    State state;

    Entry(final Stored stored, final State state) {
      this.stored = stored;
      this.state = state;
    }
  }

  /** An index position: a time (expires_at or issued_at), tie-broken by transaction hash. */
  private record Slot(long time, Hash tx) {}

  private static final Comparator<Slot> ORDER =
      Comparator.comparingLong(Slot::time).thenComparing(slot -> slot.tx().getBytes());

  private final Map<Hash, Entry> entries = new HashMap<>();
  /** Transactions the pool holds, approval or not, with when the pool reported them. */
  private final Map<Hash, Long> pooled = new HashMap<>();
  /** Transactions that left the pool since the last reconciliation, with when. */
  private final Map<Hash, Long> left = new HashMap<>();
  private final TreeSet<Slot> byExpiry = new TreeSet<>(ORDER);
  private final TreeSet<Slot> includedByIssue = new TreeSet<>(ORDER);
  private final TreeSet<Slot> orphansByIssue = new TreeSet<>(ORDER);
  private final int capacity;
  private final long graceMs;
  private final LongSupplier clock;

  /**
   * @param capacity approvals held at most
   * @param graceMs age, from issued_at, below which an approval is never evicted for a new one
   */
  public ApprovalStore(final int capacity, final long graceMs, final LongSupplier clock) {
    this.capacity = capacity;
    this.graceMs = graceMs;
    this.clock = clock;
  }

  /**
   * Stores one batch's approvals, all or nothing. Re-delivering what is stored, or an approval that
   * ranks lower than the stored one, changes nothing and still succeeds.
   *
   * @return false when the store has no room for the approvals it would have to add; then nothing
   *     changed, not even an eviction
   */
  public synchronized boolean putAll(
      final String keyId, final long issuedAt, final long expiresAt, final List<Approval> approvals) {
    final long now = clock.getAsLong();
    // Within a batch issued_at and key id are shared: the greatest fingerprint wins a duplicate.
    final Map<Hash, Stored> offered = new LinkedHashMap<>();
    for (final Approval a : approvals) {
      offered.merge(a.txHash(), new Stored(a, keyId, issuedAt, expiresAt), (held, next) -> rank(next, held) > 0 ? next : held);
    }
    final List<Stored> changes = new ArrayList<>();
    int added = 0;
    for (final Stored s : offered.values()) {
      final Entry e = entries.get(s.approval().txHash());
      if (e == null) {
        added++;
        changes.add(s);
      } else if (!e.stored.usableAt(now) || rank(s, e.stored) > 0) {
        changes.add(s);
      }
    }
    final int shortfall = added - (capacity - entries.size());
    if (shortfall > 0) {
      final List<Hash> victims = victims(shortfall, now, offered.keySet());
      if (victims.size() < shortfall) {
        return false;
      }
      victims.forEach(this::remove);
    }
    changes.forEach(this::upsert);
    return true;
  }

  /** The replacement order: issued_at unsigned, then key id and fingerprint bytewise. */
  static int rank(final Stored a, final Stored b) {
    int c = Long.compareUnsigned(a.issuedAt(), b.issuedAt());
    if (c == 0) {
      c = Arrays.compareUnsigned(a.keyId().getBytes(StandardCharsets.US_ASCII), b.keyId().getBytes(StandardCharsets.US_ASCII));
    }
    if (c == 0) {
      c = Arrays.compareUnsigned(a.approval().fingerprint().getBytes().toArrayUnsafe(), b.approval().fingerprint().getBytes().toArrayUnsafe());
    }
    return c;
  }

  /** Up to {@code wanted} evictable approvals, in eviction order; never one the batch replaces. */
  private List<Hash> victims(final int wanted, final long now, final Set<Hash> keep) {
    final List<Hash> out = new ArrayList<>(wanted);
    final Set<Hash> chosen = new HashSet<>();
    for (final Slot slot : byExpiry) {
      if (out.size() == wanted || slot.time() > now) {
        break;
      }
      if (!keep.contains(slot.tx()) && chosen.add(slot.tx())) {
        out.add(slot.tx());
      }
    }
    for (final TreeSet<Slot> index : List.of(includedByIssue, orphansByIssue)) {
      for (final Slot slot : index) {
        if (out.size() == wanted || now - slot.time() < graceMs) {
          break; // ordered by issued_at: everything after this one is younger still
        }
        if (!keep.contains(slot.tx()) && chosen.add(slot.tx())) {
          out.add(slot.tx());
        }
      }
    }
    return out;
  }

  private void upsert(final Stored s) {
    final Hash tx = s.approval().txHash();
    final Entry held = entries.get(tx);
    if (held != null) {
      unindex(tx, held);
      held.stored = s;
      index(tx, held);
      return;
    }
    final Entry entry = new Entry(s, pooled.containsKey(tx) ? State.POOLED : State.ORPHAN);
    entries.put(tx, entry);
    index(tx, entry);
  }

  private void index(final Hash tx, final Entry e) {
    byExpiry.add(new Slot(e.stored.expiresAt(), tx));
    switch (e.state) {
      case INCLUDED -> includedByIssue.add(new Slot(e.stored.issuedAt(), tx));
      case ORPHAN -> orphansByIssue.add(new Slot(e.stored.issuedAt(), tx));
      case POOLED -> {}
    }
  }

  private void unindex(final Hash tx, final Entry e) {
    byExpiry.remove(new Slot(e.stored.expiresAt(), tx));
    includedByIssue.remove(new Slot(e.stored.issuedAt(), tx));
    orphansByIssue.remove(new Slot(e.stored.issuedAt(), tx));
  }

  private void remove(final Hash tx) {
    final Entry e = entries.remove(tx);
    if (e != null) {
      unindex(tx, e);
    }
  }

  private void setState(final Hash tx, final State state) {
    final Entry e = entries.get(tx);
    if (e != null && e.state != state) {
      unindex(tx, e);
      e.state = state;
      index(tx, e);
    }
  }

  public synchronized Optional<Stored> get(final Hash txHash) {
    final Entry e = entries.get(txHash);
    return e == null ? Optional.empty() : Optional.of(e.stored);
  }

  /** The pool admitted this transaction (again, after a reorganisation): its approval is pooled. */
  public synchronized void pooled(final Hash txHash) {
    pooled.put(txHash, clock.getAsLong());
    left.remove(txHash);
    setState(txHash, State.POOLED);
  }

  /** The pool dropped or replaced this transaction: its approval becomes an orphan. */
  public synchronized void unpooled(final Hash txHash) {
    pooled.remove(txHash);
    left.put(txHash, clock.getAsLong());
    final Entry e = entries.get(txHash);
    if (e != null && e.state == State.POOLED) {
      setState(txHash, State.ORPHAN);
    }
  }

  /** A canonical block included this transaction: kept for a reorganisation, evictable first. */
  public synchronized void included(final Hash txHash) {
    pooled.remove(txHash);
    left.put(txHash, clock.getAsLong());
    setState(txHash, State.INCLUDED);
  }

  /** Releases the approvals of transactions whose block is final. */
  public synchronized void removeAll(final Collection<Hash> txHashes) {
    txHashes.forEach(this::remove);
  }

  /** Removes every approval whose expires_at has passed; memory hygiene, never a grant. */
  public synchronized int evictExpired() {
    final long now = clock.getAsLong();
    int evicted = 0;
    while (!byExpiry.isEmpty() && byExpiry.first().time() <= now) {
      remove(byExpiry.first().tx());
      evicted++;
    }
    return evicted;
  }

  /**
   * Aligns the pooled set with a snapshot of the pool, in case an event was missed. Events newer
   * than the snapshot win over it: a transaction reported pooled after the snapshot was taken stays
   * pooled (a stale snapshot must never turn a live approval into an evictable one), and one that
   * left the pool after it — dropped or included — is not made pooled again. An included approval
   * is never changed by a snapshot; only the pool's own event returns it to the pool.
   */
  public synchronized void reconcile(final Set<Hash> poolSnapshot, final long takenAt) {
    for (final Hash tx : new ArrayList<>(pooled.keySet())) {
      if (!poolSnapshot.contains(tx) && pooled.get(tx) < takenAt) {
        unpooled(tx);
      }
    }
    for (final Hash tx : poolSnapshot) {
      final Long leftAt = left.get(tx);
      final Entry e = entries.get(tx);
      if ((leftAt != null && leftAt >= takenAt) || (e != null && e.state == State.INCLUDED)) {
        continue;
      }
      pooled.putIfAbsent(tx, takenAt);
      setState(tx, State.POOLED);
    }
    left.values().removeIf(at -> at < takenAt);
  }

  public synchronized int size() {
    return entries.size();
  }

  public int capacity() {
    return capacity;
  }
}

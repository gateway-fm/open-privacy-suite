package ops.approvals;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Which approvals may be released, and when. A transaction's approval is needed for as long as
 * the transaction can return to the pool, which is until the block that includes it is
 * <em>final</em>. Every block is recorded as it is added (canonical or not, empty or not) and
 * released along the finalized chain by walking parent links from the finalized head; a block on
 * a losing fork is never released by another chain's finality and keeps its approvals until they
 * expire.
 *
 * <p>Expiry bounds the tracking (wire contract §6), in two steps. A block's transactions are
 * dropped once all its approvals have expired: the store evicts expired approvals whatever the
 * block's finality. Its parent link stays until no approval anywhere can still be alive — the
 * longest TTL a batch may have, plus how far ahead of the clock it may be issued — so that a block
 * whose own approvals expired, or an empty one, never cuts the walk to an older block whose
 * approvals still live. With finality lagging the head by hours, the tracked blocks are those of
 * one maximum TTL.
 */
public final class InclusionTracker {
  private static final class Included {
    final Hash parent;
    final long number;
    List<Hash> transactions;
    final long approvalsExpireAt;
    final long linkUntil;

    Included(final Hash parent, final long number, final List<Hash> transactions, final long approvalsExpireAt, final long linkUntil) {
      this.parent = parent;
      this.number = number;
      this.transactions = transactions;
      this.approvalsExpireAt = approvalsExpireAt;
      this.linkUntil = linkUntil;
    }
  }

  private final Map<Hash, Included> blocks = new HashMap<>();
  private final long linkRetentionMs;
  private Hash lastFinalized;

  /** @param linkRetentionMs how long any approval can live: the maximum TTL plus the issue skew */
  public InclusionTracker(final long linkRetentionMs) {
    this.linkRetentionMs = linkRetentionMs;
  }

  /**
   * @param transactions the block's transactions that hold approvals; empty for an empty block
   * @param approvalsExpireAt the latest expires_at among those approvals
   */
  public synchronized void recordIncluded(
      final Hash block,
      final Hash parent,
      final long number,
      final List<Hash> transactions,
      final long approvalsExpireAt,
      final long now) {
    blocks.put(block, new Included(parent, number, List.copyOf(transactions), approvalsExpireAt, now + linkRetentionMs));
  }

  /**
   * Releases every tracked block on the chain ending at {@code finalizedBlock}, walking the
   * recorded parent links until an untracked block or the previously finalized head. A block the
   * node never reported (it was added before the plugin started) ends the walk; so does one older
   * than any living approval.
   *
   * @return the transaction hashes whose approvals are no longer needed
   */
  public synchronized Set<Hash> finalizedUpTo(final Optional<Hash> finalizedBlock) {
    final Set<Hash> released = new HashSet<>();
    if (finalizedBlock.isEmpty()) {
      return released;
    }
    Hash cursor = finalizedBlock.get();
    // Bounded by the number of tracked blocks at entry (the map shrinks as blocks are
    // released): an unknown or repeated hash ends the walk.
    final int limit = blocks.size();
    for (int steps = 0; cursor != null && steps <= limit; steps++) {
      if (lastFinalized != null && cursor.getBytes().equals(lastFinalized.getBytes())) {
        break;
      }
      final Included included = blocks.remove(cursor);
      if (included == null) {
        break;
      }
      released.addAll(included.transactions);
      cursor = included.parent;
    }
    lastFinalized = finalizedBlock.get();
    return released;
  }

  /** Drops a block without finality (a fork the node discarded). */
  public synchronized Set<Hash> forget(final Hash block) {
    final Included included = blocks.remove(block);
    return included == null ? Set.of() : new HashSet<>(included.transactions);
  }

  /**
   * Drops the transactions of blocks whose approvals have all expired by {@code now}, and the
   * blocks themselves once no approval can be alive; memory hygiene.
   *
   * @return blocks dropped
   */
  public synchronized int forgetExpired(final long now) {
    final int before = blocks.size();
    blocks.values().removeIf(block -> block.linkUntil <= now);
    for (final Included block : blocks.values()) {
      if (block.approvalsExpireAt <= now && !block.transactions.isEmpty()) {
        block.transactions = List.of();
      }
    }
    return before - blocks.size();
  }

  public synchronized int trackedBlocks() {
    return blocks.size();
  }
}

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
 * <em>final</em>. Blocks are recorded as they are added (canonical or not) and released along
 * the finalized chain by walking parent links from the finalized head; a block on a losing fork
 * is never released by another chain's finality and keeps its approvals until they expire.
 *
 * <p>Expiry bounds the tracking (wire contract §6): a block is kept only until the last of its
 * approvals expires, since the store evicts expired approvals whatever the block's finality. With
 * finality lagging the head by hours, the tracked blocks are those of one approval lifetime.
 */
public final class InclusionTracker {
  private record Included(Hash parent, long number, List<Hash> transactions, long keepUntil) {}

  private final Map<Hash, Included> blocks = new HashMap<>();
  private Hash lastFinalized;

  /** @param keepUntil the latest expires_at among the approvals of the block's transactions */
  public synchronized void recordIncluded(
      final Hash block, final Hash parent, final long number, final List<Hash> transactions, final long keepUntil) {
    blocks.put(block, new Included(parent, number, List.copyOf(transactions), keepUntil));
  }

  /**
   * Releases every tracked block on the chain ending at {@code finalizedBlock}, walking the
   * recorded parent links until an untracked block or the previously finalized head. A block the
   * node never reported (it was added before the plugin started), or one already forgotten because
   * its approvals expired, ends the walk.
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
      released.addAll(included.transactions());
      cursor = included.parent();
    }
    lastFinalized = finalizedBlock.get();
    return released;
  }

  /** Drops a block without finality (a fork the node discarded). */
  public synchronized Set<Hash> forget(final Hash block) {
    final Included included = blocks.remove(block);
    return included == null ? Set.of() : new HashSet<>(included.transactions());
  }

  /** Drops the blocks whose every approval has expired by {@code now}; memory hygiene. */
  public synchronized int forgetExpired(final long now) {
    final int before = blocks.size();
    blocks.values().removeIf(block -> block.keepUntil() <= now);
    return before - blocks.size();
  }

  public synchronized int trackedBlocks() {
    return blocks.size();
  }
}

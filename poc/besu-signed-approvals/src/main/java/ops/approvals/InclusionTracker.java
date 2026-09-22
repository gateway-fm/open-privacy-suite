package ops.approvals;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Which approvals may be released, and when. A transaction's approval is needed for as long as
 * the transaction can return to the pool, which is until the block that includes it is
 * <em>final</em>. Blocks are recorded as they are added (canonical or not) and released along
 * the finalized chain by walking parent links from the finalized head; a block on a losing fork
 * is never released by another chain's finality and keeps its approvals until it is dropped.
 */
public final class InclusionTracker {
  private record Included(Hash parent, long number, List<Hash> transactions) {}

  private final Map<Hash, Included> blocks = new HashMap<>();
  private Hash lastFinalized;

  public synchronized void recordIncluded(
      final Hash block, final Hash parent, final long number, final List<Hash> transactions) {
    blocks.put(block, new Included(parent, number, List.copyOf(transactions)));
  }

  /**
   * Releases every tracked block on the chain ending at {@code finalizedBlock}, walking parents
   * through {@code parentOf} until an untracked block or the previously finalized head.
   *
   * @return the transaction hashes whose approvals are no longer needed
   */
  public synchronized Set<Hash> finalizedUpTo(
      final Optional<Hash> finalizedBlock, final Function<Hash, Hash> parentOf) {
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
      cursor = included.parent() != null ? included.parent() : parentOf.apply(cursor);
    }
    lastFinalized = finalizedBlock.get();
    return released;
  }

  /** Drops a block without finality (a fork the node discarded). */
  public synchronized Set<Hash> forget(final Hash block) {
    final Included included = blocks.remove(block);
    return included == null ? Set.of() : new HashSet<>(included.transactions());
  }

  /** Drops tracked blocks below {@code number}, returning their transactions; memory hygiene. */
  public synchronized Set<Hash> forgetBelow(final long number) {
    final Set<Hash> dropped = new HashSet<>();
    for (final Hash block : new ArrayList<>(blocks.keySet())) {
      final Included included = blocks.get(block);
      if (included.number() < number) {
        blocks.remove(block);
        dropped.addAll(included.transactions());
      }
    }
    return dropped;
  }

  public synchronized int trackedBlocks() {
    return blocks.size();
  }
}

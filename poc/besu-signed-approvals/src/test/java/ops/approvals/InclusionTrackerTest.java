package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/**
 * Approvals are released when their block is <em>final</em>, not when it is merely added: a block
 * that is reorganised away returns its transactions to the pool, and they must still find their
 * approvals there. Expiry bounds it: a block is tracked no longer than its approvals live.
 */
class InclusionTrackerTest {
  private static final long LATER = Long.MAX_VALUE;

  private static Hash h(final int v) {
    return Hash.wrap(Bytes32.leftPad(Bytes.of(v)));
  }

  @Test
  void releasesOnlyTheFinalizedChainAndKeepsReorgedBlocks() {
    final InclusionTracker tracker = new InclusionTracker();
    // Canonical: genesis(0) <- A1(11) <- A2(12). Fork: genesis <- B1(21).
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101), h(102)), LATER);
    tracker.recordIncluded(h(21), h(0), 1, List.of(h(201)), LATER);
    tracker.recordIncluded(h(12), h(11), 2, List.of(h(103)), LATER);

    // Nothing is final yet: nothing is released.
    assertTrue(tracker.finalizedUpTo(Optional.empty()).isEmpty());

    // A1 becomes final: its transactions are released; A2 and the fork are not.
    Set<Hash> released = tracker.finalizedUpTo(Optional.of(h(11)));
    assertEquals(Set.of(h(101), h(102)), released);
    assertEquals(2, tracker.trackedBlocks());

    // A2 becomes final: released; the fork block B1 stays tracked until it is dropped explicitly,
    // and its approvals are never released by finality of another chain.
    released = tracker.finalizedUpTo(Optional.of(h(12)));
    assertEquals(Set.of(h(103)), released);
    assertEquals(1, tracker.trackedBlocks());
    assertEquals(Set.of(h(201)), tracker.forget(h(21)));
    assertEquals(0, tracker.trackedBlocks());
  }

  @Test
  void finalityJumpingSeveralBlocksReleasesTheWholeSegmentOnce() {
    final InclusionTracker tracker = new InclusionTracker();
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), LATER);
    tracker.recordIncluded(h(12), h(11), 2, List.of(h(102)), LATER);
    tracker.recordIncluded(h(13), h(12), 3, List.of(h(103)), LATER);
    assertEquals(Set.of(h(101), h(102), h(103)), tracker.finalizedUpTo(Optional.of(h(13))));
    assertTrue(tracker.finalizedUpTo(Optional.of(h(13))).isEmpty());
  }

  @Test
  void aBlockReplacedAtTheSameHeightIsNotConfusedWithItsRival() {
    final InclusionTracker tracker = new InclusionTracker();
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), LATER);
    tracker.recordIncluded(h(21), h(0), 1, List.of(h(201)), LATER); // reorg: rival at height 1
    assertEquals(Set.of(h(201)), tracker.finalizedUpTo(Optional.of(h(21))));
    // The losing block's transactions are back in the pool and keep their approvals.
    assertEquals(1, tracker.trackedBlocks());
  }

  @Test
  void aBlockIsForgottenOnceEveryApprovalItHeldHasExpired() {
    // With finality lagging for hours, expiry is what bounds the tracked blocks.
    final InclusionTracker tracker = new InclusionTracker();
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), 1_000);
    tracker.recordIncluded(h(12), h(11), 2, List.of(h(102)), 2_000);
    assertEquals(0, tracker.forgetExpired(999));
    assertEquals(1, tracker.forgetExpired(1_000));
    assertEquals(1, tracker.trackedBlocks());
    assertEquals(1, tracker.forgetExpired(5_000));
    assertEquals(0, tracker.trackedBlocks());
    // Finality of a forgotten block releases nothing: the store evicted those approvals already.
    assertTrue(tracker.finalizedUpTo(Optional.of(h(12))).isEmpty());
  }
}
